import subprocess
from bird_app import *
import requests


def get_aspa(logger, hostname, port_number, pwd="krill"):
    while True:
        try:
            headers = {"Authorization": f"Bearer {pwd}",
                       "Content-Type": "application/json"}
            url = f"https://{hostname}:{port_number}/api/v1/cas/testbed/aspas"
            response = requests.request(
                "GET", url, headers=headers, verify=False)
            response.raise_for_status()  # Raises an exception for any HTTP error status codes
            # Return the response as a dictionary
            return response.json()
        except Exception as err:
            logger.debug(err)
            time.sleep(0.1)


def aspa_check(meta, aspa_info):
    """
    return True if the meta is in the aspa_info
    """
    # TODO: ipv6
    adj_provider_as = f"AS{meta['meta']['local_as']}(v4)"
    adj_customer_as = meta["meta"]["remote_as"]
    for data in aspa_info:
        if data["customer"] == int(adj_customer_as):
            return adj_provider_as in data["providers"]
    return False


class EfpUrpfApp(BirdApp):
    """
    a SAV App implementation based on modified bird
    """

    def __init__(self, agent, name, logger=None, ca_host="", ca_port=""):
        if not name.startswith("EFP-uRPF"):
            raise ValueError("name should start with 'EFP-uRPF'")
        name = name[9:].upper().split("-")
        self.type = name.pop(0)
        args = name
        self.roa = False
        self.aspa = False
        name = f"EFP-uRPF-Algorithm-{self.type}"
        if "ROA" in args:
            name += "-ROA"
            self.roa = True
        if "ASPA" in args:
            name += "-ASPA"
            self.aspa = True
            self.aspa_info = get_aspa(logger, ca_host, ca_port)
        name += "_app"
        super(EfpUrpfApp, self).__init__(agent, name, logger)
        self.rules = []

    def _init_protocols(self):
        result = self._parse_sav_protocols()
        while result == {}:
            time.sleep(0.1)
            result = self._parse_sav_protocols()
        self.protocols = result

    def _parse_sav_protocols(self):
        """
        using 'birdc show protocols' to get bird protocols
        """
        data = self._bird_cmd(cmd="show protocols")
        if data is None:
            return {}
        data = data.split("\n")
        while "" in data:
            data.remove("")
        result = []
        for row in data:
            protocol_name = row.split("\t")[0].split(" ")[0]
            if protocol_name.startswith("sav"):
                result.append(protocol_name)
        return result

    def _dict_to_rules(self, RPF_dict):
        """
        convert RPF_dict to rules
        """
        result = []
        for interface, data in RPF_dict.items():
            for prefix, as_number in data:
                rule = sav_rule_tuple(prefix, interface, self.name, as_number)
                result.append(rule)
        return result

    def _parse_import_table(self, protocol_name, channel_name="ipv4"):
        """
        using birdc show all import to get bird fib
        """
        cmd = f"show route all import table {protocol_name}.{channel_name}"
        # self.logger.debug(cmd)
        data = self._bird_cmd(cmd=cmd)
        if data.startswith("No import table in channel"):
            self.logger.warning(data)
            return {"import": {}}
        if data is None:
            return {"import": {}}
        # self.logger.debug(f"table {protocol_name}.{channel_name}")

        data = data.split("Table")
        while "" in data:
            data.remove("")
        result = {}
        for table in data:
            table_name, table_data = parse_bird_table(table, self.logger)
            result[table_name] = table_data
        # self.logger.debug(result)
        return result

    def _bird_cmd(self, cmd):
        """
        execute bird command and return the output in std
        """
        proc = subprocess.Popen(
            ["/usr/local/sbin/birdc "+cmd],
            shell=True,
            stdout=subprocess.PIPE,
            stdin=subprocess.PIPE,
            stderr=subprocess.PIPE)
        proc.stdin.write("\n".encode("utf-8"))
        proc.stdin.flush()
        proc.wait()
        out = proc.stdout.read().decode()
        temp = out.split("\n")[0]
        temp = temp.split()
        if len(temp) < 2:
            return None
        if not (temp[0] == "BIRD" and temp[-1] == "ready."):
            self.logger.error(f"birdc execute error:{out}")
            return None
        out = "\n".join(out.split("\n")[1:])
        return out

    def fib_changed(self):
        """
        fib change detected
        """
        self._init_protocols()
        old_rules = self.rules
        if self.type == "A":
            return self.algorithm_a(old_rules)
        elif self.type == "B":
            return self.algorithm_b(old_rules)

    def _parse_roa_table(self, t_name):
        cmd = "show route table "+t_name
        row_str = []
        # detect if roa table have rows and stale
        last_len = -1
        for _ in range(30):
            data = self._bird_cmd(cmd)
            row_str = data.split("\n")[1:]
            while "" in row_str:
                row_str.remove("")
            this_len = len(row_str)
            if this_len > 0:
                if this_len == last_len:
                    break
                else:
                    last_len = this_len
            time.sleep(0.1)
        if len(row_str) == 0:
            self.logger.warning("no roa info detected")
            return {}
        else:
            result = {}
            for row in row_str:
                d = row.split(" ")
                as_number = int(d[1][2:])
                prefix = d[0]
                prefix = prefix.replace('24-24', '24')
                if as_number not in result:
                    result[as_number] = set()
                result[as_number].add(prefix)
        # self.logger.debug(result)
        return result

    def algorithm_a(self, old_rules):
        """
        RFC 8704
        """
        X = {}
        all_int_in = {}
        roa_info = {}
        if self.roa:
            roa_info = self._parse_roa_table(t_name="r4")
            self.logger.debug(roa_info)
        for protocol_name in self.protocols:
            # self.logger.debug(msg=f"protocol_name:{protocol_name}")
            meta = self.agent.link_man.get(protocol_name)["meta"]
            all_int_in[protocol_name] = {"meta": meta}
            all_int_in[protocol_name]["adj-in"] = self._parse_import_table(protocol_name)[
                "import"]
            # filter out the adj-in that does not match the roa
            if self.roa:
                temp = {}
                for k, v in all_int_in[protocol_name]['adj-in'].items():
                    this_prefix = str(k)
                    this_asn = v[0]['origin_as']
                    if this_asn in roa_info:
                        if this_prefix in roa_info[this_asn]:
                            temp[k] = v
                        else:
                            self.logger.warning(f"roa mismatch for {k}:{v}")
                all_int_in[protocol_name]["adj-in"] = temp
        for protocol_name, data in all_int_in.items():
            if data["meta"]["remote_role"] == "customer":
                if self.aspa:
                    self.logger.debug(data)
                    self.logger.debug(self.aspa_info)
                    self.logger.debug(aspa_check(data, self.aspa_info))
                    if not aspa_check(data, self.aspa_info):
                        continue
                for prefix, paths in data["adj-in"].items():
                    for path in paths:
                        X[path["origin_as"]] = set()
        for origin_asn in X:
            for protocol_name, data in all_int_in.items():
                for prefix, paths in data["adj-in"].items():
                    for path in paths:
                        if path["origin_as"] == origin_asn:
                            # self.logger.debug(f"prefix:{prefix}")
                            X[origin_asn].add(prefix)
        new_rules = set()
        for protocol_name, data in all_int_in.items():
            if not data["meta"]["remote_role"] == "customer":
                # self.logger.debug(f"new_rules:{data['meta']['remote_role']}")
                continue
            for origin_asn, prefixes in X.items():
                is_prefix_included = False
                for prefix in prefixes:
                    if prefix in data["adj-in"]:
                        is_prefix_included = True
                        break
                if is_prefix_included:
                    for prefix in prefixes:
                        rule = sav_rule_tuple(
                            prefix, data["meta"]["interface_name"], self.name, origin_asn)
                        new_rules.add(rule)
        self.logger.debug(f"new_rules:{new_rules}")

        return rule_list_diff(old_rules, new_rules)

    def algorithm_b(self, old_rules):
        """
        RFC 8704
        """
        I = set()
        P = set()
        A = set()
        Q = set()
        all_int_in = []
        for protocol_name in self.protocols:
            self.logger.debug(msg=f"protocol_name:{protocol_name}")
            meta = self.agent.link_man.get(protocol_name)["meta"]
            data = {"meta": meta}
            data["adj-in"] = self._parse_import_table(protocol_name)["import"]
            all_int_in.append(data)

        for data in all_int_in:
            if data["meta"]["remote_role"] == "customer":
                interface_name = data["meta"]["interface_name"]
                if interface_name not in I:
                    I.add(interface_name)
                for prefix, paths in data["adj-in"].items():
                    for path in paths:
                        P.add((prefix, path["origin_as"]))
                        A.add(path["origin_as"])
        for data in all_int_in:
            if data["meta"]["remote_role"] in ["peer", "provider"]:
                for prefix, paths in data["adj-in"].items():
                    for path in paths:
                        if path["origin_as"] in A:
                            Q.add((prefix, path["origin_as"]))
        Z = P.union(Q)
        # self.logger.debug(f"I:{I}")
        # self.logger.debug(f"P:{P}")
        # self.logger.debug(f"A:{A}")
        # self.logger.debug(f"Q:{Q}")
        # self.logger.debug(f"Z:{Z}")
        new_rules = set()
        for interface in I:
            for prefix, origin_as in Z:
                new_rules.add(sav_rule_tuple(
                    prefix, interface, self.name, origin_as))
        # self.logger.debug(f"new_rules:{new_rules}")
        # new_rules = self._set_to_rules(I, Z)
        return rule_list_diff(old_rules, new_rules)

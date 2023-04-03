import subprocess
from bird_app import *


class EfpUrpfApp(BirdApp):
    """
    a SAV App implementation based on modified bird
    """

    def __init__(self, agent, name="efpurpf_app", logger=None):
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

    def _table_to_rules(self, table):
        """
        convert table to rules
        """
        result = []
        for as_number in table:
            for prefix in table[as_number]["prefixes"]:
                for interface_name in table[as_number]["interface_names"]:
                    result.append(sav_rule_tuple(
                        prefix, interface_name, self.name, as_number))
        return result

    def _parse_import_table(self, protocol_name, channel_name="ipv4"):
        """
        using birdc show all import to get bird fib
        """
        data = self._bird_cmd(
            cmd=f"show route all import table {protocol_name}.{channel_name}")
        if data.startswith("No import table in channel"):
            # self.logger.debug(data)
            return {"import": []}

        if data is None:
            return {"import": []}
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
        new_ = {}
        for protocol_name in self.protocols:
            peer_new = self._parse_import_table(protocol_name)
            for prefix in peer_new["import"]:
                prefix_data = peer_new["import"][prefix]
                # self.logger.debug(prefix_data)
                for data in prefix_data:
                    as_number = data["origin_as"]
                    if not as_number in new_:
                        new_[as_number] = {
                            "interface_names": [data["interface_name"]],
                            "prefixes": [prefix]
                        }
                    else:
                        temp = new_[as_number]
                        if not prefix in temp["prefixes"]:
                            temp["prefixes"].append(prefix)
                        if not data["interface_name"] in temp["interface_names"]:
                            temp["interface_names"].append(
                                data["interface_name"])
                        new_[as_number] = temp
        # self.logger.debug(new_)
        new_rules = self._table_to_rules(new_)
        add_rules = []
        del_rules = []
        for row in new_rules:
            if not row in old_rules:
                add_rules.append(row)
        for row in old_rules:
            if not row in new_rules:
                del_rules.append(row)
        self.rules = new_rules
        return add_rules, del_rules

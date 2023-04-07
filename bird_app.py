from multiprocessing import Manager
import subprocess

from sav_common import *


def str_to_scope(input_str):
    temp = decode_csv(input_str)
    result = []
    while len(temp) > 0:
        scope_len = int(temp.pop(0))
        for _ in range(scope_len):
            path_len = int(temp.pop(0))
            path = []
            for _ in range(path_len):
                path.append(temp.pop(0))
            result.append(path)
    return result


def hex_str_to_prefixes(input_bytes, t="ipv4"):
    """
    reverse of prefixes_to_hex_str
    """
    if t == "ipv4":
        result = []
        temp = decode_csv(input_bytes)
        while "" in temp:
            temp.remove("")
        while len(temp) > 0:
            prefix_len = int(temp.pop(0))
            prefix = []
            for _ in range(int((prefix_len + 7) / 8)):
                prefix.append(temp.pop(0))
            while len(prefix) < 4:
                prefix.append("0")
            result.append(netaddr.IPNetwork(
                ".".join(prefix) + "/" + str(prefix_len)))
        return result
    else:
        raise NotImplementedError


def prefixes_to_hex_str(prefix_list, ip_type="ipv4"):
    """
        constructs NLRI prefix list
        :param prefix_list: prefix in str format list
    """
    if ip_type == "ipv4":
        items = []
        for prefix in prefix_list:
            prefix = str(prefix)
            ip_address, prefix = prefix.split("/")
            items.append(prefix)
            ip_address = ip_address.split(".")
            items += ip_address[:int((int(prefix) + 7) / 8)]
        return ",".join(items)
    else:
        raise NotImplementedError


class BirdApp(SavApp):
    """
    a sav app implementation based on modified bird
    """

    def __init__(self, agent, name="bird_app", logger=None):
        super(BirdApp, self).__init__(agent, name, logger)
        self.prepared_cmd = Manager().list()
        self.pp_v4_dict = {}
        # pp represents prefix-(AS)path

    def get_pp_v4_dict(self):
        return self.pp_v4_dict

    def diff_pp_v4(self):
        """
        return adds and dels,
        which is a list of modification required(tuple of (prefix,path))
        """
        old_ = self.pp_v4_dict
        new_ = self._parse_bird_fib()
        if not "master4" in new_:
            self.logger.warning(
                "no master4 table. Is birnewd ready?")
            return [], []
        new_ = new_["master4"]
        dels = []
        adds = []
        # here we only uses the as_path of each prefix
        for prefix in new_:
            temp = []
            for item in new_[prefix]:
                if "as_path" in item:
                    temp.append(item["as_path"])
            temp.sort()
            new_[prefix] = temp
        # self.logger.debug(new_)
        for prefix in new_:
            if prefix not in old_:
                for path in new_[prefix]:
                    adds.append((prefix, path))
            else:
                if new_[prefix] != old_[prefix]:
                    for path in old_[prefix]:
                        if not path in new_[prefix]:
                            dels.append((prefix, path))
                    for path in new_[prefix]:
                        if not path in old_[prefix]:
                            adds.append((prefix, path))
        for prefix in old_:
            if prefix not in new_:
                for path in old_[prefix]:
                    dels.append((prefix, path))
        self.pp_v4_dict = new_
        return adds, dels

    def _parse_bird_fib(self):
        """
        using birdc show all to get bird fib
        """
        data = self._bird_cmd(cmd="show route all")
        if data is None:
            return {}
        data = data.split("Table")
        while "" in data:
            data.remove("")
        result = {}
        for table in data:
            table_name, table_data = parse_bird_table(table, self.logger)
            result[table_name] = table_data
        # self.logger.debug(result)
        return result

    def _parse_protocol_meta(self, protocol_name):
        # TODO: implement reading other info
        data = self._bird_cmd(cmd=f"show protocols all {protocol_name}")
        if data is None:
            return {}
        meta = {}
        data = data.split("\n")
        for line in data:
            if "Role:" in line:
                meta["remote_role"] = line.split(":")[1].strip()
            elif "Neighbor AS" in line:
                meta["remote_as"] = line.split(":")[1].strip()
        self.logger.debug(data)
        self.logger.debug(meta)
        return meta

    def send_msg(self, msg):
        """
        notify the bird to retrieve the msg from flask server and execute it.
        """
        if not isinstance(msg, dict):
            self.logger.error("msg is not a dictionary")
            return
        while len(self.prepared_cmd) > 0:
            self.logger.warn(
                f"last message not finished {self.prepared_cmd}")
            time.sleep(0.01)
        # specialized for bird app, we need to convert the msg to byte array
        msg_byte = self._msg_to_hex_str(msg)
        self.add_prepared_cmd(msg_byte)
        self._bird_cmd(cmd="call_agent")
        msg1 = msg
        if "sav_nlri" in msg1:
            msg1["sav_nlri"] = list(map(str, msg1["sav_nlri"]))
        if "sav_origin" in msg1:
            while [] in msg1["sav_scope"]:
                msg1["sav_scope"].remove([])
            msg1["sav_scope"] = list(
                map(lambda x: list(map(int, x)), msg1["sav_scope"]))
        self.logger.info(
            f"SENT MSG ON LINK [{msg['protocol_name']}]:{msg}, time_stamp: [{time.time()}]]")

    def _msg_to_hex_str(self, msg):
        """
        msg is in json format,but bird is difficult to use,
        therefore we transfer the msg to byte array,
        and put that into the json for bird app
        """
        for k in ["msg_type", "protocol_name", "as4_session", "sav_nlri", "is_interior"]:
            if k not in msg:
                self.logger.error(
                    f"required key :[{k}] missing in msg:{msg}")
                return None
        hex_str_msg = {}
        is_as4 = msg["as4_session"]
        hex_str_msg["sav_nlri"] = prefixes_to_hex_str(msg["sav_nlri"])
        hex_str_msg["nlri_len"] = len(decode_csv(hex_str_msg["sav_nlri"]))
        m_t = msg["msg_type"]
        hex_str_msg["protocol_name"] = msg["protocol_name"]
        hex_str_msg["next_hop"] = msg["src"].split(".")
        hex_str_msg["next_hop"] = [
            str(len(hex_str_msg["next_hop"]))] + hex_str_msg["next_hop"]
        hex_str_msg["next_hop"] = ",".join(hex_str_msg["next_hop"])
        hex_str_msg["sav_scope"] = scope_to_hex_str(
            msg["sav_scope"], msg["is_interior"], is_as4)
        hex_str_msg["is_interior"] = 1 if msg["is_interior"] else 0
        if msg["is_interior"]:
            as_path_code = "2"
            hex_str_msg["withdraws"] = "0,0"
            hex_str_msg["sav_origin"] = ",".join(asn_to_hex(
                msg["sav_origin"], is_as4))
            if m_t == "origin":
                # insert origin for sav
                # using ba_origin, there is no need to convert tot as4
                hex_str_msg["as_path"] = ",".join(
                    [as_path_code, "1", hex_str_msg["sav_origin"]])
                hex_str_msg["as_path_len"] = len(
                    decode_csv(hex_str_msg["as_path"]))
                # insert asn_paths
                return hex_str_msg
            elif m_t == "relay":
                as_number = str(len(msg["sav_path"]))
                temp = path_to_hex(msg["sav_path"], is_as4)
                hex_str_msg["as_path"] = ",".join(
                    [as_path_code, as_number]+temp)
                hex_str_msg["as_path_len"] = len(
                    decode_csv(hex_str_msg["as_path"]))
                return hex_str_msg
            else:
                self.logger.error(f"unknown msg_type: {m_t}")

        else:
            hex_str_msg["withdraws"] = "0,0"
            hex_str_msg["sav_origin"] = ",".join(
                ipv4_str_to_hex(msg["sav_origin"]))
            return hex_str_msg

    def add_prepared_cmd(self, cmd):
        self.prepared_cmd.append(cmd)

    def get_prepared_cmd(self):
        return self.prepared_cmd.pop(0)

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
            self.logger.warning(f"birdc give empty result:[{out}];{temp}")
            return None
        if not (temp[0] == "BIRD" and temp[-1] == "ready."):
            self.logger.error(f"birdc execute error:{out}")
            return None

        out = "\n".join(out.split("\n")[1:])
        return out

    def fib_changed(self, adds, dels):
        """
        fib change dectected
        """
        adds, dels = self.diff_pp_v4()
        # currently we only support ipv4
        if len(adds) == 0 and len(dels) == 0:
            return

        self.logger.error(adds)
        self.logger.error(dels)

    def recv_msg(self, msg):
        # self.logger.debug("app {} got msg {}".format(self.name, msg))
        m_t = msg["msg_type"]
        if m_t == "link_state_change":
            if msg["msg"] == "up":
                self.put_link_up(msg["protocol_name"])
            elif msg["msg"] == "down":
                self.put_link_down(msg["protocol_name"])
            else:
                raise ValueError(f"unknown msg:{msg}")
        elif m_t in ["bird_bgp_config", "bgp_update"]:
            msg["source_app"] = self.name
            msg["source_link"] = msg["msg"]["protocol_name"]
            self.put_link_up(msg["source_link"])
            if m_t == "bgp_update":
                msg["msg"] = self.preprocess_msg(msg["msg"])
            self.agent.put_msg(msg)
        else:
            self.logger.error(
                "unknown msg_type: {m_t}\n msg :{msg}")

    def preprocess_msg(self, msg):
        # as_path is easier to process in string format, so we keep it
        # process routes
        msg["routes"] = decode_csv(input_str=msg["routes"])
        msg["add_routes"] = []
        msg["del_routes"] = []
        for route in msg["routes"]:
            if route[0] == "+":
                msg["add_routes"].append(netaddr.IPNetwork(route[1:]))
            elif route[0] == "-":
                msg["del_routes"].append(netaddr.IPNetwork(route[1:]))
        del msg["routes"]
        # process sav_nlri
        msg["sav_nlri"] = hex_str_to_prefixes(msg["sav_nlri"])

        # process sav_scope
        msg["sav_scope"] = str_to_scope(msg["sav_scope"])

        # process as_path, only used for inter-msgs
        msg["as_path"] = decode_csv(msg["as_path"])
        msg["is_native_bgp"] = not (len(msg["sav_nlri"]) > 0)
        # self.logger.debug(msg)
        return msg

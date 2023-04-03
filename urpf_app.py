from sav_common import *


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


class UrpfApp(SavApp):
    """
    a SavApp implementation of uRPF
    strict, loose
    """

    def __init__(self, agent, name="_urpf_app", mode="strict", logger=None):
        valid_modes = ["strict", "loose"]
        if mode not in valid_modes:
            raise ValueError(f"mode must be one of {valid_modes}")
        name = mode + name
        self.mode = mode
        super(UrpfApp, self).__init__(agent, name, logger)
        self.fib = []

    def fib_changed(self, adds, dels):
        """
        generate sav rule based on the latest fib,
        only add is implemented
        """
        # TODO: implement del
        # self.logger.debug(f"app {self.name} fib_changed")
        # remove local prefixes
        temp = []
        for row in adds:
            if not '0.0.0.0' in row['Gateway']:
                temp.append(row)
        adds = temp
        temp = []
        for row in dels:
            if not '0.0.0.0' in row['Gateway']:
                temp.append(row)
        dels = temp
        if self.mode == "strict":
            return self._fib_changed_strict(adds, dels)
        elif self.mode == "loose":
            return self._fib_changed_loose(adds, dels)

    def _fib_changed_strict(self, adds, dels):
        """
        generate sav rule based on the latest fib
        return a list of add_rules, del_rules
        """
        add_rules = []
        del_rules = []
        for row in adds:
            prefix = netaddr.IPNetwork(
                row["Destination"]+"/"+row["Genmask"])
            add_rules.append(sav_rule_tuple(
                prefix, row.get("Iface"), self.name))
        for row in dels:
            prefix = netaddr.IPNetwork(
                row["Destination"]+"/"+row["Genmask"])
            del_rules.append(sav_rule_tuple(
                prefix, row.get("Iface"), self.name))
        return add_rules, del_rules

    def _fib_changed_loose(self, adds, dels):
        """
        generate sav rule based on the latest fib
        """
        add_rules = []
        del_rules = []
        for row in adds:
            prefix = netaddr.IPNetwork(
                row["Destination"]+"/"+row["Genmask"])
            add_rules.append(sav_rule_tuple(prefix, "*", self.name))
        for row in dels:
            prefix = netaddr.IPNetwork(
                row["Destination"]+"/"+row["Genmask"])
            del_rules.append(sav_rule_tuple(prefix, "*", self.name))
        return add_rules, del_rules

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
            return
        # specialized for bird app, we need to convert the msg to byte array
        msg_byte = self._msg_to_hex_str(msg)
        self.add_prepared_cmd(msg_byte)
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
        # output = proc.stdout.read().decode()
        # self.logger.debug(
        # "birdc call_agent{} [{}]".format(time.time(), output))

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
                return
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

    def recv_msg(self, msg):
        self.logger.debug(f"app {self.name} got msg {msg}")
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
            self.logger.error(f"unknown msg_type: {m_t}\n msg :{msg}")

# -*-coding:utf-8 -*-
"""
@File    :   app_efp_urpf.py
@Time    :   2023/07/24
@Version :   0.1

@Desc    :   the app_efp_urpf.py is responsible for EFP-uRPF-SAV rule generation
"""

from common import *
EFP_URPF_A_ID = "efp_urpf_a"
EFP_URPF_B_ID = "efp_urpf_b"
EFP_URPF_A_ROA_ID = "efp_urpf_a_roa"
EFP_URPF_B_ROA_ID = "efp_urpf_b_roa"
EFP_URPF_A_ASPA_ID = "efp_urpf_a_aspa"
EFP_URPF_B_ASPA_ID = "efp_urpf_b_aspa"
EFP_URPF_A_ROA_ASPA_ID = "efp_urpf_a_roa_aspa"
EFP_URPF_B_ROA_ASPA_ID = "efp_urpf_b_roa_aspa"


class EfpUrpfApp(SavApp):
    """
    a SAV App implementation based on reference router (BIRD)
    only works for interior links
    """

    def __init__(self, agent, name, logger=None):
        self.pp_v4_dict = {}
        # pp represents prefix-(AS)path
        self.ifa_map = {
            "inter": {
                "provider": NOT_SPECIFIED,
                "customer": ALLOW_LIST,
                "peer": NOT_SPECIFIED},
            "intra": NOT_SPECIFIED}
        raw_name = name
        name = name[9:].upper().split("_")
        if "A" in name:
            self.type = "A"
        elif "B" in name:
            self.type = "B"
        else:
            raise ValueError(f"unknown type {name}")
        if "ROA" in name:
            self.roa = True
        else:
            self.roa = False
        if "ASPA" in name:
            self.aspa = True
        else:
            self.aspa = False
        super(EfpUrpfApp, self).__init__(agent, raw_name, logger)

    def _init_protocols(self):
        """
        get all protocol names that starts with sav
        """
        self.protocol_metas = []
        for link_meta in self.agent.link_man.get_all_bgp_links().values():
            if not link_meta["is_interior"]:
                continue
                # only works for interior links
            if link_meta["link_type"] in BGP_LINK_TYPES:
                self.protocol_metas.append(link_meta)

    def _dict_to_rules(self, RPF_dict):
        """
        convert RPF_dict to rules
        """
        result = []
        for interface, data in RPF_dict.items():
            for prefix, as_number in data:
                rule = get_sav_rule(prefix, interface, self.app_id, as_number)
                result.append(rule)
        return result

    def _parse_import_table(self, protocol_name):
        """
        using birdc show all import to get bird fib
        """
        return self.agent.get_adj_in(protocol_name)

    def generate_sav_rules(self, fib_adds, fib_dels, old_rules):
        """
        fib change detected
        """
        self._init_protocols()
        if self.type == "A":
            return self.algorithm_a(old_rules)
        elif self.type == "B":
            return self.algorithm_b(old_rules)
        # TODO update self.rules

    def _aspa_check(self, meta, aspa_info, my_as):
        """
        return True if the adj-customer-as is in the aspa_info and the adj-provider-as is in the aspa_info
        otherwise return False
        """
        # self.logger.debug(meta)
        # self.logger.debug(aspa_info)
        # self.logger.debug(my_as)
        adj_customer_as = meta["remote_as"]
        # self.logger.debug(adj_customer_as)
        if not adj_customer_as in aspa_info:
            return False
        return my_as in aspa_info[adj_customer_as]

    def algorithm_a(self, old_rules):
        """
        RFC 8704
        """
        X = {}
        all_int_in = {}
        if self.roa:
            roa_info = self.agent.get_roa_info()
        if self.aspa:
            aspa_info = self.agent.get_aspa_info()
        # self.logger.debug(self.protocol_metas)
        for meta in self.protocol_metas:
            protocol_name = meta["protocol_name"]
            # only works for interior links
            all_int_in[protocol_name] = {"meta": meta}
            all_int_in[protocol_name]["adj-in"] = self.agent.get_adj_in(
                protocol_name)
            # filter out the adj-in that does not match the roa
            if self.roa:
                temp = {}
                for this_prefix, v in all_int_in[protocol_name]['adj-in'].items():
                    this_asn = v[0]['origin_as']
                    if this_asn in roa_info:
                        if this_prefix in roa_info[this_asn]:
                            temp[this_prefix] = v
                        else:
                            self.logger.warning(
                                f"roa mismatch: adj-in info:  {this_asn}:{this_prefix}\nroa info:{roa_info[this_asn]}")
                all_int_in[protocol_name]["adj-in"] = temp
        # self.logger.debug(f"EFP-A all_int_in:{all_int_in}")
        for protocol_name, data in all_int_in.items():
            if not data["meta"]["remote_role"] == "customer":
                continue
            if self.aspa:
                if not self._aspa_check(data["meta"], aspa_info, self.agent.config["local_as"]):
                    self.logger.debug(f"aspa check failed: {data['meta']}")
                    self.logger.debug(f"aspa check failed: {aspa_info}")
                    self.logger.debug(
                        f"aspa check failed: {self.agent.config['local_as']}")
                    continue
            for prefix, prefix_data in data["adj-in"].items():
                for path in prefix_data["srcs"]:
                    X[path["as_path"][0]] = set()
        for origin_asn in X:
            for protocol_name, data in all_int_in.items():
                for prefix, prefix_data in data["adj-in"].items():
                    for path in prefix_data["srcs"]:
                        if path["as_path"][0] == origin_asn:
                            # self.logger.debug(f"prefix:{prefix}")
                            X[origin_asn].add(prefix)
        # self.logger.debug(f"EFP-A X:{X}")
        new_rules = {}
        # self.logger.debug(all_int_in)
        all_customer_ifas = []
        for protocol_name, data in all_int_in.items():
            if data["meta"]["remote_role"] == "customer":
                all_customer_ifas.append(data["meta"]["interface_name"])
        ifas_to_go = []
        for data in all_int_in.values():
            if not data["meta"]["remote_role"] == "customer":
                continue
            for origin_asn, prefixes in X.items():
                # self.logger.debug(f"{data['meta']['interface_name']}:{prefixes}")
                # self.logger.debug(f"{data['adj-in'].keys()}")
                is_prefix_included = False
                for prefix in prefixes:
                    if prefix in data["adj-in"]:
                        is_prefix_included = True
                        break
                if is_prefix_included:
                    ifas_to_go.append(data["meta"]["interface_name"])
                    break
        for ifa in ifas_to_go:
            for origin_asn, prefixes in X.items():
                for p in prefixes:
                    rule = get_sav_rule(p, ifa, self.app_id, origin_asn)
                    new_rules[get_key_from_sav_rule(rule)] = rule
        # self.logger.debug(f"EFP-A new_rules:{new_rules}")

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
        for link_meta in self.protocol_metas:
            protocol_name = link_meta["protocol_name"]
            # self.logger.debug(msg=f"protocol_name:{protocol_name}")
            data = {"meta": link_meta}
            data["adj-in"] = self.agent.get_adj_in(protocol_name)
            all_int_in.append(data)

        for data in all_int_in:
            if data["meta"]["remote_role"] == "customer":
                interface_name = data["meta"]["interface_name"]
                if interface_name not in I:
                    I.add(interface_name)
                for prefix, prefix_data in data["adj-in"].items():
                    for path in prefix_data["srcs"]:
                        origin_as = path["as_path"][0]
                        P.add((prefix, origin_as))
                        A.add(origin_as)
        for data in all_int_in:
            if data["meta"]["remote_role"] in ["peer", "provider"]:
                # self.logger.debug(
                # f"protocol_name:{data['meta']['protocol_name']}:{data['adj-in'].keys()}")
                for prefix, prefix_data in data["adj-in"].items():
                    for origin_as in prefix_data["origin_ases"]:
                        # self.logger.debug(f"{prefix}:{origin_as}")
                        if origin_as in A:
                            Q.add((prefix, origin_as))
        Z = P.union(Q)
        # self.logger.debug(f"I:{I}")
        # self.logger.debug(f"P:{P}")
        # self.logger.debug(f"A:{A}")
        # self.logger.debug(f"Q:{Q}")
        # self.logger.debug(f"Z:{Z}")
        new_rules = {}
        for interface in I:
            for prefix, origin_as in Z:
                r = get_sav_rule(prefix, interface, self.app_id, origin_as)
                new_rules[get_key_from_sav_rule(r)] = r
        # self.logger.debug(f"EFP-B new_rules:{new_rules}")
        # new_rules = self._set_to_rules(I, Z)
        return rule_list_diff(old_rules, new_rules)

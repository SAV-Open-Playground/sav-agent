# -*-coding:utf-8 -*-
"""
@File    :   app_efp_urpf.py
@Time    :   2023/07/24
@Version :   0.1

@Desc    :   the app_efp_urpf.py is responsible for EFP-uRPF-SAV rule generation
"""

from common.sav_common import *
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
    """

    def __init__(self, agent, name, logger=None, ca_host="", ca_port=""):
        self.pp_v4_dict = {}
        # pp represents prefix-(AS)path
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
            self.aspa_info = get_aspa(logger, ca_host, ca_port)
        else:
            self.aspa = False
        super(EfpUrpfApp, self).__init__(agent, raw_name, logger)

    def _init_protocols(self):
        """
        get all protocol names that starts with sav
        """
        self.protocol_metas = []
        for link_name,link_meta in self.agent.link_man.get_all_link_meta().items():
            if not link_meta["is_interior"]:
                continue
                # only works for interior links
            if link_meta["link_type"] in ["dsav"]:
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
        default = {"import":{}}
        ret = birdc_get_import(self.logger, protocol_name, "ipv4")
        if ret == default:
            ret = birdc_get_import(self.logger, protocol_name, "rpdp4")
        return ret

    def generate_sav_rules(self, fib_adds, fib_dels, bird_fib_change_dict, old_rules):
        """
        fib change detected
        """
        self._init_protocols()
        if self.type == "A":
            return self.algorithm_a(old_rules)
        elif self.type == "B":
            return self.algorithm_b(old_rules)
        # TODO update self.rules

    def algorithm_a(self, old_rules):
        """
        RFC 8704
        """
        X = {}
        all_int_in = {}
        roa_info = {}
        if self.roa:
            roa_info = self._parse_roa_table(t_name="r4")
            self.logger.debug(f"roa_info: {roa_info}")
        
        for meta in self.protocol_metas:
            protocol_name = meta["protocol_name"]
            all_int_in[protocol_name] = {"meta": meta}
            all_int_in[protocol_name]["adj-in"] = self._parse_import_table(
                protocol_name)
            # self.logger.debug(msg=f"all_int_in:{all_int_in[protocol_name]['adj-in']}")
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
        # self.logger.debug(f"EFP-A all_int_in:{all_int_in}")
        for protocol_name, data in all_int_in.items():
            self.logger.debug(data)
            if data["meta"]["remote_role"] == "customer":
                if self.aspa:
                    # self.logger.debug(data)
                    # self.logger.debug(self.aspa_info)
                    # self.logger.debug(aspa_check(data, self.aspa_info))
                    if not aspa_check(data, self.aspa_info):
                        continue
                for prefix, paths in data["adj-in"].items():
                    # self.logger.debug(f"{prefix}, {paths}")
                    for path in paths:
                        X[path["origin_as"]] = set()
        # self.logger.debug(f"EFP-A X:{X}")
        for origin_asn in X:
            for protocol_name, data in all_int_in.items():
                for prefix, paths in data["adj-in"].items():
                    for path in paths:
                        if path["origin_as"] == origin_asn:
                            # self.logger.debug(f"prefix:{prefix}")
                            X[origin_asn].add(prefix)
        # self.logger.debug(f"EFP-A X:{X}")
        new_rules = {}
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
                        rule = get_sav_rule(
                            prefix, data["meta"]["interface_name"], self.app_id, origin_asn)
                        new_rules[get_key_from_sav_rule(rule)]=rule
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
            data["adj-in"] = self._parse_import_table(protocol_name)
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
        new_rules = {}
        for interface in I:
            for prefix, origin_as in Z:
                r =get_sav_rule(prefix, interface, self.app_id, origin_as)
                new_rules[get_key_from_sav_rule(r)] = r
        # self.logger.debug(f"EFP-B new_rules:{new_rules}")
        # new_rules = self._set_to_rules(I, Z)
        return rule_list_diff(old_rules, new_rules)

# -*-coding:utf-8 -*-
"""
@File    :   app_efp_urpf.py
@Time    :   2023/07/24
@Author  :   Yuqian Shi
@Version :   0.1

@Desc    :   the app_efp_urpf.py is responsible for EFP-uRPF-SAV rule generation
"""

from multiprocessing import Manager
from sav_common import *


class EfpUrpfApp(SavApp):
    """
    a SAV App implementation based on reference router (BIRD)
    """

    def __init__(self, agent, name, logger=None, ca_host="", ca_port=""):
        self.prepared_cmd = Manager().list()
        self.pp_v4_dict = {}
        # pp represents prefix-(AS)path
        src_ip = agent.config.get("grpc_id")
        link_man = agent.link_man
        local_as = agent.config.get("local_as")
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
        data = birdc_show_protocols(self.logger)
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
        
        return birdc_get_import(self.logger,protocol_name,channel_name)

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
        # self.logger.debug(f"EFP-A old_rules:{old_rules}")
        for protocol_name in self.protocols:
            # self.logger.debug(msg=f"protocol_name:{protocol_name}")
            link_data = self.agent.link_man.get(protocol_name)
            if link_data is None:
                self.logger.warning(f"get link data error for link:{protocol_name}")
                self.logger.warning(f"self.agent.link_man:{self.agent.link_man}")
                self.logger.warning(f"self.agent:{self.agent}")
                continue
            meta = link_data["meta"]
            
            all_int_in[protocol_name] = {"meta": meta}
            all_int_in[protocol_name]["adj-in"] = self._parse_import_table(protocol_name)
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
        for protocol_name in self.protocols:
            # self.logger.debug(msg=f"protocol_name:{protocol_name}")
            meta = self.agent.link_man.get(protocol_name)["meta"]
            data = {"meta": meta}
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
        new_rules = set()
        for interface in I:
            for prefix, origin_as in Z:
                new_rules.add(sav_rule_tuple(
                    prefix, interface, self.name, origin_as))
        # self.logger.debug(f"EFP-B new_rules:{new_rules}")
        # new_rules = self._set_to_rules(I, Z)
        return rule_list_diff(old_rules, new_rules)

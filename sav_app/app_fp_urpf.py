# -*-coding:utf-8 -*-
"""
@File    :   app_fp_urpf.py
@Time    :   2023/07/24
@Version :   0.1
@Desc    :   the app_fp_urpf.py is responsible for Fp-uRPF-SAV rule generation
"""

from common import *
FP_URPF_ID = "fp_urpf"


class FpUrpfApp(SavApp):
    """
    fp-uRPF:
    the idea is using prefix as a link between interfaces and origin (maybe AS or a device)
    packet with same origin is allowed from all linked interfaces.
    e.g.:
    FIB:
    Prefix        Interface   Origin
    P1          I1          O1
    P2          I2          O1
    ==>
    SAV:
    Prefix        Interface
    P1          I1
    P2          I1
    P1          I2
    P2          I2


    however, the sav rule is still prefix based. we expand a origin to all prefixes it has using fib table.
    """

    def __init__(self, agent, name, logger=None):
        super(FpUrpfApp, self).__init__(agent, name, logger)

    def _get_prefix_interface_table(self):
        """
        build prefix interface table
        """
        origin_interfaces_table = {}
        origin_prefix_table = {}
        for prefix, srcs in self.agent.get_fib("bird", ["remote"]).items():
            # self.logger.debug(prefix)
            if prefix.version in [4, 6]:
                for line in srcs:
                    if "origin_asn" in line:
                        origin = line["origin_asn"]
                        if not origin in origin_prefix_table:
                            origin_prefix_table[origin] = set()
                            origin_interfaces_table[origin] = set()
                        origin_prefix_table[origin].add(prefix)
                    else:
                        self.logger.error(f"no origin_asn in {prefix}:{line}")
                    # self.logger.debug(line)
                    interface = line.get("interface_name", None)
                    if interface:
                        origin_interfaces_table[origin].add(interface)
            else:
                raise ValueError(f"unknown ip version {prefix.version}")
        my_asn = self.agent.config["local_as"]
        if not my_asn in origin_prefix_table:
            origin_prefix_table[my_asn] = set()
            origin_interfaces_table[my_asn] = set()
        for prefix, srcs in self.agent.get_fib("bird", ["local"]).items():
            self.logger.debug((prefix, srcs))
            if prefix.version in [4, 6]:
                for line in srcs:
                    origin_prefix_table[my_asn].add(prefix)
                    interface = line.get("interface_name", None)
                    if interface:
                        origin_interfaces_table[my_asn].add(interface)
                    else:
                        interface = line.get("device", None)
                    if interface:
                        origin_interfaces_table[my_asn].add(interface)
            else:
                raise ValueError(f"unknown ip version {prefix.version}")
        return origin_interfaces_table, origin_prefix_table

    def generate_sav_rules(self, fib_adds, fib_dels, old_rules):
        """
        only implement the inter-as mode
        """
        origin_interfaces_table, origin_prefix_table = self._get_prefix_interface_table()
        # self.logger.debug(f"origin_interfaces_table={origin_interfaces_table}")
        # self.logger.debug(f"origin_prefix_table={origin_prefix_table}")
        add_dict = {}
        del_set = set()
        new_rules = {}
        for origin, interfaces in origin_interfaces_table.items():
            for prefix in origin_prefix_table[origin]:
                for ifa in interfaces:
                    new_rule = get_sav_rule(prefix, ifa, self.app_id)
                    new_rule_key = get_key_from_sav_rule(new_rule)
                    if not new_rule_key in old_rules:
                        add_dict[new_rule_key] = new_rule
                    new_rules[new_rule_key] = new_rule
        for r_k in old_rules:
            if not r_k in new_rules:
                del_set.add(r_k)
        self.rules = new_rules
        # self.logger.debug(f"new_rules={new_rules}")
        # self.logger.debug(f"{self.app_id}: add_rules={add_dict}")
        # self.logger.debug(f"{self.app_id}: del_rules={del_set}")
        return add_dict, del_set

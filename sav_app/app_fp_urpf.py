# -*-coding:utf-8 -*-
"""
@File    :   app_fp_urpf.py
@Time    :   2023/07/24
@Version :   0.1

@Desc    :   the app_fp_urpf.py is responsible for Fp-uRPF-SAV rule generation
"""

from common.sav_common import *


class FpUrpfApp(SavApp):
    """
    a SAV App implementation based on modified bird
    """

    def __init__(self, agent, name="fpurpf_app", logger=None):
        super(FpUrpfApp, self).__init__(agent, name, logger)
        self.rules = {}

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

    def _table_to_rules(self, table):
        """
        convert table to rules
        """
        result = []
        for as_number in table:
            self.logger.debug(table[as_number])
            for prefix in table[as_number]["prefixes"]:
                self.logger.debug(table[as_number]["interface_names"])
                for interface_name in table[as_number]["interface_names"]:
                    result.append(get_sav_rule(
                        prefix, interface_name, self.name, as_number))
        return result

    def fib_changed(self):
        """
        fib change detected
        """
        # self._init_protocols()
        new_ = self.agent.get_kernel_fib()
        # we need prefix-interface table

        for prefix, row in new_.items():
            temp = []
            temp.append(row["Iface"])
            new_[prefix] = temp
        # self.logger.debug(f"new_:{new_}")
        old_rules = self.rules
        add_rules = []
        del_rules = []
        for prefix in new_:
            if prefix in old_rules:
                for interface_name in new_[prefix]:
                    if not interface_name in old_rules[prefix]:
                        add_rules.append(get_sav_rule(
                            prefix, interface_name, self.name))
                for interface_name in old_rules[prefix]:
                    if not interface_name in new_[prefix]:
                        del_rules.append(get_sav_rule(
                            prefix, interface_name, self.name))
            else:
                for interface_name in new_[prefix]:
                    add_rules.append(get_sav_rule(
                        prefix, interface_name, self.name))
        for prefix in old_rules:
            if not prefix in new_:
                for interface_name in old_rules[prefix]:
                    del_rules.append(get_sav_rule(
                        prefix, interface_name, self.name))
        self.rules = new_
        # self.logger.debug(f"{self.name}: add_rules={add_rules}")
        # self.logger.debug(f"{self.name}: del_rules={del_rules}")
        return add_rules, del_rules
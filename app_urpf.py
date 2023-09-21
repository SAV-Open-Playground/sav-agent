# -*-coding:utf-8 -*-
"""
@File    :   app_urpf.py
@Time    :   2023/07/24
@Version :   0.1

@Desc    :   the app_urpf.py is responsible for uRPF-SAV rule generation (Strict and Loose)
"""

from sav_common import *


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

    def fib_changed(self, adds, dels):
        """
        generate sav rule based on the latest fib,
        only add is implemented
        """
        # TODO: implement del
        # self.logger.debug(f"app {self.name} fib_changed")
        # remove local prefixes
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
        for prefix, row in adds.items():
            add_rules.append(sav_rule_tuple(
                prefix, row.get("Iface"), self.name))
        for prefix, row in adds.items():
            del_rules.append(sav_rule_tuple(
                prefix, row.get("Iface"), self.name))
        return add_rules, del_rules

    def _fib_changed_loose(self, adds, dels):
        """
        generate sav rule based on the latest fib
        """
        add_rules = []
        del_rules = []
        for prefix, row in adds.items():
            add_rules.append(sav_rule_tuple(prefix, "*", self.name))
        for prefix, row in adds.items():
            del_rules.append(sav_rule_tuple(prefix, "*", self.name))
        return add_rules, del_rules

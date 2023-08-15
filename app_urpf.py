# -*-coding:utf-8 -*-
"""
@File    :   app_urpf.py
@Time    :   2023/07/24
@Author  :   Yuqian Shi
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
        self.fib = []

    def fib_changed(self, adds, dels):
        """
        generate sav rule based on the latest fib,
        only add is implemented
        """
        # TODO: implement del
        # self.logger.debug(f"app {self.name} fib_changed")
        # remove local prefixes
        adds = remove_local(adds)
        dels = remove_local(dels)
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
            # self.put_link_up(msg["source_link"])
            if "rpdp" in msg["msg"]["channels"]:
                self.set_link_type(msg["source_link"], "modified_bgp")
            else:
                self.set_link_type(msg["source_link"],"native_bgp")
            if m_t == "bgp_update":
                msg["msg"] = self.preprocess_msg(msg["msg"])
            self.agent.put_msg(msg)
        else:
            self.logger.error(f"unknown msg_type: {m_t}\n msg :{msg}")

# -*- coding: utf-8 -*-
"""
-------------------------------------------------
   File Name:     data_plane_interface
   Description :
   Author :       MichaelYoung
   date:          2023/12/27
-------------------------------------------------
   Change Activity:
                   2023/12/27:
-------------------------------------------------
"""
import json
from common.logger import LOGGER as logger
from data_plane.sav_rule_manager import SavRuleManager
from data_plane.iptables import IPTableManager
from data_plane.access_control_list import AccessControlListManager


class Interceptor:
    sav_rule_manager = SavRuleManager()
    iptables = IPTableManager()
    acl = AccessControlListManager()

    def __int__(self):
        pass

    def iptables_enable(self, rules, active_app):
        return self.iptables.enable(rules=rules, active_app=active_app)

    def iptables_tc_enable(self, rules):
        return self.iptables.tc_enable(rules=rules)

    def acl_enable(self, rules):

        self.acl.acl_generator(rules=rules)
        return

    def enable(self, active_app, tool="iptables", limit_rate=None):
        try:
            if active_app is None:
                logger.debug("active app is None")
                return
            # TODO dynamic changing
            # tell if current node is sav enabled
            with open('/root/savop/SavAgent_config.json', 'r') as f:
                config = json.load(f)
                app_list = config.get("apps")
            if active_app not in app_list:
                logger.debug("active app isn't in the enable scope")
                return
            sav_rules = self.sav_rule_manager.get_sav_rules_by_app(app_name=active_app)
            if len(sav_rules) == 0:
                return f"there is no {active_app} sav rules, " \
                    f"so don't need to refresh iptables"
            if (tool == "iptables") and (limit_rate is None):
                self.iptables_enable(rules=sav_rules, active_app=active_app)
            elif (tool == "iptables") and (limit_rate is not None):
                self.iptables_tc_enable(sav_rules)
            elif tool == "acl":
                self.acl_enable(rules=sav_rules)
        except Exception as e:
            logger.error(e)
            logger.exception(e)
            return f"refresh {active_app} iptables failed"

interceptor = Interceptor()




# -*- coding: utf-8 -*-
"""
-------------------------------------------------
   File Name:     sav_rule_manager
   Description :
   Author :       MichaelYoung
   date:          2023/12/27
-------------------------------------------------
   Change Activity:
                   2023/12/27:
-------------------------------------------------
"""


class SavRuleManager:
    def get_sav_rules_by_app(self, app_name):
        from control_plane import SA
        sav_rule = SA.get_sav_rules_by_app(app_name=app_name)
        return sav_rule

    def get_interface_info(self):
        from control_plane import SA
        return SA.get_interface_info()

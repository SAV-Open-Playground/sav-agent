# -*- coding: utf-8 -*-
"""
-------------------------------------------------
   File Name：     sav_rule_manager
   Description :
   Author :       MichaelYoung
   date：          2023/12/27
-------------------------------------------------
   Change Activity:
                   2023/12/27:
-------------------------------------------------
"""
import copy
from netaddr import IPNetwork

class SavRuleManager:
    def get_sav_rules_by_app(self, app_name):
        from control_plane import SA
        sav_rule = SA.get_sav_rules_by_app(app_name=app_name)
        # sav_rule = {'rpdp_app': {
        #     '111.192.3.0/24_65502_eth_r2': {'prefix': IPNetwork('111.192.3.0/24'), 'interface_name': 'eth_r2',
        #                                     'source_app': 'rpdp_app', 'origin': 65502, 'is_interior': True,
        #                                     'create_time': 1703660119.005739, 'update_time': 1703660119.005739},
        #     '111.192.7.0/24_65503_eth_r3': {'prefix': IPNetwork('111.192.7.0/24'), 'interface_name': 'eth_r3',
        #                                     'source_app': 'rpdp_app', 'origin': 65503, 'is_interior': True,
        #                                     'create_time': 1703660119.207284, 'update_time': 1703660119.207284},
        #     '111.192.4.0/24_65503_eth_r3': {'prefix': IPNetwork('111.192.4.0/24'), 'interface_name': 'eth_r3',
        #                                     'source_app': 'rpdp_app', 'origin': 65503, 'is_interior': True,
        #                                     'create_time': 1703660119.207284, 'update_time': 1703660119.207284},
        #     'fec::4:0/120_65503_eth_3': {'prefix': IPNetwork('fec::4:0/120'), 'interface_name': 'eth_3',
        #                                  'source_app': 'rpdp_app', 'origin': 65503, 'is_interior': True,
        #                                  'create_time': 1704361380.2991848, 'update_time': 1704361380.2991848},
        #     'fec::7:0/120_65503_eth_3': {'prefix': IPNetwork('fec::7:0/120'), 'interface_name': 'eth_3',
        #                                  'source_app': 'rpdp_app', 'origin': 65503, 'is_interior': True,
        #                                  'create_time': 1704361380.2991848, 'update_time': 1704361380.2991848},
        #     'fec::3:0/120_65502_eth_2': {'prefix': IPNetwork('fec::3:0/120'), 'interface_name': 'eth_2',
        #                                  'source_app': 'rpdp_app', 'origin': 65502, 'is_interior': True,
        #                                  'create_time': 1704361380.318601, 'update_time': 1704361380.318601}}}
        return sav_rule.get(app_name, {})

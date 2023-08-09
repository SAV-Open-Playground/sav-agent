# -*-coding:utf-8 -*-
"""
@File    :   app_bar.py
@Time    :   2023/07/24
@Author  :   Yuqian Shi
@Version :   0.1

@Desc    :   the app_bar.py is responsible for BAR-SAV rule generation (when ROA and ASPA are available)
"""
from sav_common import *

class BarApp(SavApp):
    """
    a SavApp implementation of BAR-SAV (ASPA and ROA required)
    """
    def __init__(self, agent, name="bar_app", logger=None):
        super(BarApp, self).__init__(agent, name, logger)
        self.rules = []
        #TODO update and change detection
    def _update_rpki_cache(self):
        """
        TODO will wait untill we have roa and aspa info
        """
        while True:
            self.roa_cache = get_roa(self.logger)
            self.aspa_cache = get_aspa(self.logger)
            good = True
            if len(self.roa_cache) == 0:
                self.logger.warning("empty roa")
                good = False
            if len(self.aspa_cache)==0:
                self.logger.warning("empty aspa")
                good = False
            if good:
                return
            else:
                time.sleep(0.1)
    def _get_peer_as(self):
        """
        return a set of AS numbers of all customer or peer asn
        """
        data = birdc_get_protos_by(self.logger,'Proto','BGP')
        all_protos = [i['Name'] for i in data]
        result = set()
        for proto_name in all_protos:
            meta = self.agent.link_man.get(proto_name)["meta"]
            if meta["remote_role"] in ["customer","peer"]:
                result.add(meta["remote_as"])
        return result
    def fib_changed(self):
        """
        Althgough ASPA and ROA is included, only BGP update(FIB change) will trigger BAR to generate rules
        """
        # get all custoer or lateral peer
        return self.procedure_x()
    def cal_cc_using_aspa(self):
        local_as = self.agent.config["local_as"]
        
        aspa = self.aspa_cache
        result = [local_as]
        added = True
        while added:
            added = False
            for customer_as,providers in aspa.items():
                if element_exist_check(result,providers):
                    asn = int(customer_as)
                    if not asn in result:
                        result.append(asn)
                        added = True
        result = result[1:] # remove loacal as
        return result
    def procedure_x(self):
        """
        A description of Procedure X (one that makes use of only ASPA and ROA data):
        Step A: Compute the set of ASNs in the Customer's or Lateral Peer's customer cone using ASPA data.
        Step B: Compute from ROA data the set of prefixes authorized to be announced by the ASNs found in Step A. Keep only the unique prefixes. This set is the permissible prefix list for SAV for the interface in consideration.
        """
        new_rules = set()
        
        self._update_rpki_cache()
        # find direct connected customer or peer
        links_data = self.agent.link_man.data
        direct = {}
        # A:
        for link_name,link_data in links_data.items():
            link_meta = link_data["meta"]
            # self.logger.debug(list(link_data.keys()))
            if "bgp" in link_data["link_type"]:
                if link_data["meta"]["local_role"] in["peer","provider"]:
                    direct[link_data["meta"]["interface_name"]] =link_data["meta"]["remote_as"]
            else:
                # self.logger.debug(link_data)
                pass
        # B:
        for interface,asn in direct.items():
            allowed_prefix = get_p_by_asn(asn,self.roa_cache,self.aspa_cache)
            for p,origin_as in allowed_prefix.items():
                rule = sav_rule_tuple(p, interface, self.name, origin_as)
                new_rules.add(rule)
        return rule_list_diff(self.rules,new_rules)
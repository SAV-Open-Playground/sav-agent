# -*-coding:utf-8 -*-
"""
@File    :   app_bar.py
@Time    :   2023/07/24
@Version :   0.1
@Desc    :   the app_bar.py is responsible for BAR-SAV rule generation (when ROA and ASPA are available)
"""
from common import *
BAR_ID = "bar"


class BarApp(SavApp):
    """
    a SavApp implementation of BAR-SAV (ASPA and ROA required)
    """

    def __init__(self, agent, name="BAR", logger=None):
        super(BarApp, self).__init__(agent, name, logger)
        self.rules = []
        # TODO update and change detection

    def _update_rpki_cache(self):
        """
        TODO will wait until we have roa and aspa info
        """
        for i in range(50):
            roa_cache = self.agent.get_roa_info()
            aspa_cache = self.agent.get_aspa_info()
            good = True
            if len(roa_cache) == 0:
                self.logger.warning("empty roa")
                good = False
            if len(aspa_cache) == 0:
                self.logger.warning("empty aspa")
                good = False
            if good:
                return roa_cache, aspa_cache
            else:
                time.sleep(0.1)
                self.logger.warning(
                    f"{self.app_id} getting rkpi cache failed {i+1}, retrying")

    def _get_peer_as(self):
        """
        return a set of AS numbers of all customer or peer asn
        """
        data = birdc_get_protos_by(self.logger, 'Proto', 'LINK_BGP')
        all_protos = [i['Name'] for i in data]
        result = set()
        for proto_name in all_protos:
            self.logger.debug(proto_name)
            meta = self.agent.bird_man.get_link_meta_by_name(proto_name)
            if meta["remote_role"] in ["customer", "peer"]:
                result.add(meta["remote_as"])
        return result

    def generate_sav_rules(self, fib_adds, fib_dels, old_rules):
        """
        Although ASPA and ROA is included, only LINK_BGP update(FIB change) will trigger BAR to generate rules
        """
        # get all customer or lateral peer
        return self.procedure_x(old_rules)

    def cal_cc_using_aspa(self):
        local_as = self.agent.config["local_as"]
        aspa = self.aspa_cache
        result = [local_as]
        added = True
        while added:
            added = False
            for customer_as, providers in aspa.items():
                if element_exist_check(result, providers):
                    asn = int(customer_as)
                    if not asn in result:
                        result.append(asn)
                        added = True
        result = result[1:]  # remove loacal as
        return result

    def procedure_x(self, old_rule_dict):
        """
        A description of Procedure X (one that makes use of only ASPA and ROA data):
        Step A: Compute the set of ASNs in the Customer's or Lateral Peer's customer cone using ASPA data.
        Step B: Compute from ROA data the set of prefixes authorized to be announced by the ASNs found in Step A. Keep only the unique prefixes. This set is the permissible prefix list for SAV for the interface in consideration.
        """

        roa_cache, aspa_cache = self._update_rpki_cache()
        # find direct connected customer or peer
        links_data = self.agent.link_man.get_all_link_meta()
        direct = {}
        new_rules = {}
        # A:
        for link_name, link_meta in links_data.items():
            if not link_meta["is_interior"]:
                continue
            if link_meta["link_type"] in ["dsav", "bgp"]:  # dsav also implies as relationship
                if link_meta["local_role"] in ["peer", "provider"]:
                    direct[link_meta["interface_name"]
                           ] = link_meta["remote_as"]
        # self.logger.debug(f"direct:{direct}")
        # B:
        for interface, asn in direct.items():
            allowed_prefix = get_p_by_asn(asn, roa_cache, aspa_cache)
            for p, origin_as in allowed_prefix.items():
                rule = get_sav_rule(p, interface, self.app_id, origin_as)
                new_rules[get_key_from_sav_rule(rule)] = rule
        self.logger.debug(f"new_rules:{new_rules}")
        return rule_list_diff(old_rule_dict, new_rules)

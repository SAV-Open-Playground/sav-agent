"""
@File    :   app_bicone.py
@Time    :   2024/04/198
@Version :   0.1

@Desc    :   the app_bicone.py is responsible for BICONE-SAV rule generation
"""

import re
from common import *
BICONE_ID = "bicone"


class BiconeApp(SavApp):
    """
    a sav app implementation based on reference router (based on bird)
    embedded grpc link
    """

    def __init__(self, agent, name, logger=None):
        super(BiconeApp, self).__init__(agent, name, logger)
        self.prefix_as_path_dict = {}  # key is prefix,value is AS path
        self.connect_objs = {}
        self.metric = self.get_init_metric_dict()
        self.stub_dict = {}
        self.spa_data = {"inter": {}, "intra": {}}
        self.spd_data = {"inter": {}, "intra": {}}
        self.id2prefix_dict = {}
        # local rule cache
        self.spd_sn_dict = {}
        self.spa_sn_dict = {}
        self.ifa_map = {
            "inter": {
                "provider": NOT_SPECIFIED,
                "customer": BLOCK_LIST,
                "peer": BLOCK_LIST},
            "intra": NOT_SPECIFIED}

    def get_init_metric_dict(self):
        ret = {}
        for k in RPDP_LINK_TYPES:
            ret[k] = init_protocol_metric()
        return ret

    def _aspa_check(self, customer: int, provider: int, aspa_data: dict):
        if not customer in aspa_data:
            return False
        if not provider in aspa_data[customer]:
            return False
        return True

    def generate_sav_rules(self, fib_adds, fib_dels, old_rules):
        """
        if reset is True, will use empty dict as old_
        """
        Z = {1: set()}
        provder_links = set()
        # key is the level of that asn
        all_bgp_links = self.agent.link_man.get_all_bgp_links()
        for link_name, link_meta in all_bgp_links.items():
            if link_meta["remote_role"] == "provider":
                Z[1].add(link_meta["remote_as"])
                provder_links.add(link_name)
        self.logger.debug(f"Z: {Z}")
        self.logger.debug(f"provder_links: {provder_links}")
        as_paths = []

        for link_name in provder_links:
            for p_d in self.agent.get_adj_in(link_name).values():
                for src in p_d["srcs"]:
                    if "as_path" in src:
                        if len(src["as_path"]) > 1:
                            if src["as_path"] in as_paths:
                                continue
                            as_paths.append(src["as_path"])
        self.logger.debug(f"as_paths: {as_paths}")
        aspa_data = self.agent.get_aspa_info()
        # self.logger.debug(aspa_data)
        for as_path in as_paths:
            # the as_path here has been reversed once
            i = 0
            # self.logger.debug(as_path)
            while i + 1 < len(as_path):
                provider = as_path[i]
                customer = as_path[i+1]
                i += 1
                if not self._aspa_check(customer, provider, aspa_data):
                    self.logger.warning(
                        f"invalid aspa data for {customer} {provider}")
                    continue
                for j in range(i, len(as_path)):
                    Z[1].add(as_path[j])
        # self.logger.debug(f"Z: {Z}")
        k = 2
        # build next level of Z
        while True:
            Z[k] = set()
            for asn in Z[k-1]:
                if not asn in aspa_data:
                    continue
                for provider in aspa_data[asn]:
                    if not provider in Z[k-1]:
                        Z[k].add(provider)
            if len(Z[k]) == 0:
                del Z[k]
                break
            else:
                for asn in Z[k-1]:
                    Z[k].add(asn)
                k += 1
        k_max = max(Z.keys())
        roa_info = self.agent.get_roa_info()
        self.logger.debug(f"roa_info: {roa_info}")
        prefixes = set()
        # add prefixes based on roa info
        for asn in Z[k_max]:
            if not asn in roa_info:
                # self.logger.warning(f"no aspa data for {asn}")
                continue
            for p in roa_info[asn]:
                prefixes.add(p)
        # add prefixes based on Adj-RIBs-In info
        for link_name in provder_links:
            for p in self.agent.get_adj_in(link_name).keys():
                prefixes.add(p)

        new_rules = []
        all_bgp_links = self.agent.link_man.get_all_bgp_links()
        for link_meta in all_bgp_links.values():
            if link_meta["remote_role"] == "provider":
                continue
            for p in prefixes:
                new_rules.append(get_sav_rule(
                    p, link_meta["interface_name"], self.app_id))
        add_dict, del_set = self.diff_rules(old_rules, new_rules)
        return add_dict, del_set

#!/usr/bin/python3
# -*-coding:utf-8 -*-
"""
@File    :   const_values.py
@Time    :   2024/03/19
@Author  :   Yuqian Shi
@Version :   0.1
@Contact :   yuqian.shi@outlook.com
@Desc    :   The const_values.py contains all the constant values used in the project.
"""
import netaddr
#
ASN_TYPE = int
IP_ADDR_TYPE = netaddr.IPAddress
PREFIX_TYPE = netaddr.IPNetwork
TIMEIT_THRESHOLD = 0.5
# SAV-AGENT
LOG_FOR_FRONT_KEY_WORD = "LOG_FOR_FRONT"
BGP_UPDATE_DATA_MAX_LEN = 65516

# SAV_APP:RPDP
DEFAULT_MIIG_TYPE = 0
DEFAULT_MIIG_TAG = 0
LINK_RPDP_HTTP = 'rpdp-http'
LINK_RPDP_GRPC = 'rpdp-grpc'
LINK_RPDP_BGP = 'dsav'  # RPDP OVER BGP LINK AND BGP LINK NOT sending BGP INFO
LINK_NATIVE_BGP = 'bgp'
LINK_PHYSICAL = 'physical'
LINK_BGP_WITH_RPDP = 'bgp_rpdp'  # RPDP WITH BGP info
BGP_LINK_TYPES = [LINK_NATIVE_BGP, LINK_BGP_WITH_RPDP, LINK_RPDP_BGP]
RPDP_LINK_TYPES = [LINK_RPDP_HTTP, LINK_RPDP_BGP,LINK_BGP_WITH_RPDP]
SPA = "spa"
SPD = "spd"
ALLOW_LIST = "allow_list"
BLOCK_LIST = "block_list"
ALL_ALLOW = "all_allow"
ALL_BLOCK = "all_block"
NOT_SPECIFIED = "not_specified"
ALLOW_INTERFACE_LIST = "allow_interface_list"

VALIDATE_MODES = [ALLOW_LIST, BLOCK_LIST, ALL_BLOCK, ALL_ALLOW, NOT_SPECIFIED]
# the edge router that work as the representative of the edge routers
RT_EDGE_REP = 'edge_rep'
RT_EDGE = 'edge'  # the edge router that has external links
RT_CORE = 'core'  # the router that only has internal links
ROUTER_LOCATIONS = [RT_EDGE_REP, RT_EDGE, RT_CORE]
IFA_INTRA = "intra-interface"
IFA_INTER_FULL_KNOWLEDGE = "inter-interface-full-knowledge"
IFA_INTER_PARTIAL_KNOWLEDGE = "inter-interface-partial-knowledge"
FILTER_MODE = ["allow_list","deny_list"]
VIRTUAL_INTERFACE = "eth_veth"
INTERFACE_TYPES = [IFA_INTRA,
                   IFA_INTER_FULL_KNOWLEDGE, IFA_INTER_PARTIAL_KNOWLEDGE]
HARDCODE_KEYS = {"dev ": "interface_name",
                      "Type: ": "type",
                      "BGP.origin:": "origin",
                      "BGP.as_path:": "as_path",
                      "via ": "via",
                      "BGP.next_hop: ": "next_hop",
                      "BGP.local_pref: ": "metric",
                      "BGP.otc: ": "only_to_customer",
                      "BGP.community: ": "community",
                      "Kernel.source: ": "kernel_source",
                      "Kernel.metric: ": "Kernel_metric",
                      "BGP.originator_id: ": "origin_router_id",
                      "BGP.cluster_list: ": "cluster_list"}
MULT_HOMING_FULL = 1
MULT_HOMING_PARTIAL = 0 
SOLE_HOMING = 2
PREFIX_TYPES = [MULT_HOMING_FULL, MULT_HOMING_PARTIAL, SOLE_HOMING]

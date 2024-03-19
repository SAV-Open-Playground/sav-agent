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
RPDP_OVER_HTTP = 'rpdp-http'
RPDP_OVER_GRPC = 'rpdp-grpc'
RPDP_OVER_BGP = 'dsav'
NATIVE_BGP = 'bgp'
BGP_WITH_RPDP = 'bgp-rpdp'
BPG_LINK_TYPES = [NATIVE_BGP, BGP_WITH_RPDP]
RPDP_LINK_TYPES = [RPDP_OVER_HTTP, RPDP_OVER_BGP]
SPA = "spa"
SPD = "spd"

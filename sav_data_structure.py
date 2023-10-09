#!/usr/bin/python3
# -*-coding:utf-8 -*-
"""
@File    :   data_structure.py
@Time    :   2023/08/08
@Version :   0.1
@Desc    :   The data_structure.py is responsible  project defined data structure and related conversions
"""
import netaddr

# AS


def is_asn(in_put):
    if isinstance(in_put, int):
        if in_put > 0 and in_put < 65535:
            return True
    return False

def asn2hex(asn, as_session=False):
    """
        convert asn to hex
        :param asn: asn (str)
        :return: hex value list (u8)
    """
    temp = hex(int(asn))[2:]
    result = []
    if len(temp) % 2 == 1:
        result.append(str(int(temp[:1], 16)))
        temp = temp[1:]
    while len(temp):
        result.append(str(int(temp[:2], 16)))
        temp = temp[2:]
    length = 2
    if as_session:
        length = 4
    while len(result) < length:
        result = ["0"] + result
    return result
# IP

# prefix


def is_prefix(in_put):
    return isinstance(in_put, netaddr.IPNetwork)


def prefix2str(prefix):
    """
    convert netaddr prefix to string
    """
    if not isinstance(prefix, netaddr.IPNetwork):
        raise TypeError(
            "prefix should be netaddr.IPNetwork,but get {}".format(type(prefix)))
    return str(prefix.ip) + "/" + str(prefix.prefixlen)


def str2prefix(prefix):
    """
    convert string prefix to netaddr prefix
    """
    if not isinstance(prefix, str):
        raise TypeError("prefix should be str,but get {}".format(type(prefix)))
    return netaddr.IPNetwork(prefix)
# Path


def path2hex(asn_path, as4_session=False):
    """
        convert asn_path to hex
        :param asn_path: list of asn
        :return: hex value list (u8)
    """
    result = []
    for path in list(map(lambda x: asn2hex(x, as4_session), asn_path)):
        result += path
    return result


# SPA
def inter_spa2nlri_hex(msg):
    """
        convert inter-spa to nlri
        :param msg: inter-spa message
        :return: nlri in json
    """
    msg = {

        "length": 0,  # length to the en
    }


def get_inter_spa(origin_as, prefixes):
    msg = {
        "type": 2,
        "origin_as": origin_as,
        "prefixes": prefixes,
        "flag": 1
    }
    return msg


# description of all msg used between functions,each key must have a description
SAV_META = {
    "example": {
        "description": "bgp update message",
        "key_types": []
    }
}

# sa_agent in_buff msg
def is_in_buff_msg(msg):
    pass
    # if not isinstance(msg, dict):
    #     return False
    # if "type" not in msg:
    #     return False
    # if msg["type"] not in SAV_META:
    #     return False
    # if "key_types" not in SAV_META[msg["type"]]:
    #     return False
    # for key in SAV_META[msg["type"]]["key_types"]:
    #     if key not in msg:
    #         return False
    # return True
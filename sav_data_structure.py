#!/usr/bin/python3
# -*-coding:utf-8 -*-
"""
@File    :   data_structure.py
@Time    :   2023/08/08
@Author  :   Yuqian Shi
@Version :   0.1
@Desc    :   The data_structure.py is responsible  project defined data structure and related conversions
"""
import netaddr

# AS
def is_asn(in_put):
    if isinstance(in_put,int):
        if in_put > 0 and in_put < 65535:
            return True
    return False 
def asn2hex(asn, as_session=False):
    """
        convert asn to hex
        :param asn: asn (str)
        :return: hex value list (u8)
    """
    if as_session:
        result = hex(int(asn))[2:]
        temp = []
        while len(result) >= 2:
            temp.append(str(int(result[:2], 16)))
            result = result[2:]
        result = temp
        while len(result) < 4:
            result = ["0"] + result
        return result

    result = hex(int(asn))[2:]
    temp = []
    while len(result) >= 2:
        temp.append(str(int(result[:2], 16)))
        result = result[2:]
    result = temp
    return result
# IP 

# prefix
def isprefix(in_put):
    return isinstance(in_put,netaddr.IPNetwork)
def prefix2str(prefix):
    """
    convert netaddr prefix to string
    """
    if not isinstance(prefix, netaddr.IPNetwork):
        raise TypeError("prefix should be netaddr.IPNetwork,but get {}".format(type(prefix)))
    return str(prefix.ip) + "/" + str(prefix.prefixlen)
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
        
        "length":0,# length to the en
    }
    
def get_inter_spa(origin_as,prefixes):
    msg = {
        "type":2,
        "origin_as":origin_as,
        "prefixes":prefixes,
        "flag":1
    }
    return msg
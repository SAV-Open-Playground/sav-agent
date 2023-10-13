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

BGP_UPDATE_DATA_MAX_LEN = 65516
def is_asn(in_put):
    if isinstance(in_put, int):
        if in_put > 0 and in_put < 65535:
            return True
    return False


def keys_types_check(d, key_types):
    """
    raise KeyError if key is missing
    raise TypeError if key is not the right type
    """
    for k, t in key_types:
        if not k in d:
            raise KeyError(f"{k} missing in {d.keys()}")
        if not isinstance(d[k], t):
            raise TypeError(f"{k} should be {t} but {type(d[k])} found")


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
    return str(prefix)


def str2prefix(prefix):
    """
    convert string prefix to netaddr prefix
    """
    if not isinstance(prefix, str):
        raise TypeError("prefix should be str,but get {}".format(type(prefix)))
    return netaddr.IPNetwork(prefix)

def prefix_to_nlri(prefix,ip_type="ipv4"):
    """
    convert prefix to nlri (csv str)
    """
    if ip_type == "ipv4":
        prefix = str(prefix)
        ip_address, prefix = prefix.split("/")
        ip_address = ip_address.split(".")
        items = [prefix]
        items += ip_address[:int((int(prefix) + 7) / 8)]
        return items
    else:
        raise NotImplementedError
    
def prefixes_to_hex_str(prefix_list, ip_type="ipv4"):
    """
        constructs NLRI prefix list
        :param prefix_list: prefix in str format list
    """
    if ip_type == "ipv4":
        items = []
        for prefix in prefix_list:
            items.extend(prefix_to_nlri(prefix,ip_type))
        return ",".join(items)
    else:
        raise NotImplementedError

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


def get_intra_spd_dict():
    """get a human readable intra-spd message"""
    msg = {
        "type": 2,
        "sub_type": 1,
        "length": 0,
        "sn": 0,
        "origin_router_id": "",
        "opt_data_len": 0,
        "opt_data": "",
        "addresses": []
    }
    return msg


def get_intra_spd_nlri_dict():
    """get a human readable intra-spd-nlri message"""
    nlri = {
        "afi": 0,
        "safi": 0,
        "next_hoop_len": 0,
        "next_hop": "",
        "reserved": 0,
        "nlri": ""
    }
    return nlri


def get_intra_spa_dict():
    """get a human readable intra-spa message"""
    msg = {
        "afi": 0,
        "safi": 0,
        "next_hoop_len": 0,
        "reserved": 0,
        "nlri_data": [],
    }
    return msg


def get_intra_spa_nlri_hex(origin_router_id,prefix,flag,miig_type=0,miig_tag=0):
    """
    get a intra-spa-nlri message in hex,
    length is calculated when converting to nlri
    flag: 0:source flag,1:destination flag
    """
    
    nlri = [
        1, # route type
        origin_router_id # origin router id
    ]
    nlri.extend(prefix_to_nlri(prefix)) # prefix
    nlri.append(miig_type)
    nlri.append(flag)
    nlri.append(miig_tag)
    nlri.insert(1,1+1+4+len(nlri[2])+1+1+4)
    return nlri

def intra_spa2nlri_hex(nlri_dict):
    """
        convert intra-spa to nlri
        :param msg: intra-spa message
        :return: nlri in json
    """
    ret = [
        nlri_dict["route_type"],
        (nlri_dict["prefix"]),
        nlri_dict
        ]
    ret.append

# description of all msg used between functions,each key must have a description
SAV_META = {
    "example": {
        "description": "bgp update message",
        "key_types": []
    }
}


def get_send_buff_msg(src_app, type, argv, msg, retry_forever, response):
    argv["retry_forever"] = retry_forever
    argv["response"] = response
    ret = {"source_app": src_app, "type": type, "argv": argv, "msg": msg}
    check_send_buff_msg(ret)
    return ret


def check_send_buff_msg(msg):
    """
    check if the msg is a valid msg to put in send buff
    """
    key_types = [("source_app", str), ("type", str),
                 ("argv", dict), ("msg", _)]
    keys_types_check(msg, key_types)
    keys_types_check(msg["argv"], ("retry_forever", bool), ("response", bool))

    # def is_in_buff_msg(msg):
    # pass
    # # if not isinstance(msg, dict):
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


def init_direction_metric():
    return {"count": 0, "time": 0.0, "size": 0,"wait_time": 0.0}


def init_protocol_metric():
    return {"recv": init_direction_metric(),
            "send": init_direction_metric(),
            "start": None,
            "end": None}
    
def get_agent_to_bird_msg():
    msg = {
        "type":"",
        "pkt_data":""
        
    }
    
def decode_csv(input_str):
    """
    return a list of strings
    """
    if input_str == "":
        return []
    if "," in input_str:
        return input_str.split(",")

    return [input_str]
    
def hex_str_to_prefixes(input_bytes, t="ipv4"):
    """
    reverse of prefixes_to_hex_str
    """
    if t == "ipv4":
        result = []
        temp = decode_csv(input_bytes)
        while "" in temp:
            temp.remove("")
        while len(temp) > 0:
            prefix_len = int(temp.pop(0))
            prefix = []
            for _ in range(int((prefix_len + 7) / 8)):
                prefix.append(temp.pop(0))
            while len(prefix) < 4:
                prefix.append("0")
            result.append(netaddr.IPNetwork(
                ".".join(prefix) + "/" + str(prefix_len)))
        return result
    else:
        raise NotImplementedError
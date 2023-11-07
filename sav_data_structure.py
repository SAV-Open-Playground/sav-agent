#!/usr/bin/python3
# -*-coding:utf-8 -*-
"""
@File    :   data_structure.py
@Time    :   2023/08/08
@Version :   0.1
@Desc    :   The data_structure.py is responsible  project defined data structure and related conversions
"""
import netaddr


def int2hex(input_int, zfill_length=4):
    temp = hex(input_int)[2:]
    ret = []
    if len(temp) % 2 == 1:
        ret.append(int(temp[:1], 16))
        temp = temp[1:]
    while len(temp):
        ret.append(int(temp[:2], 16))
        temp = temp[2:]
    while len(ret) < zfill_length:
        ret.insert(0, 0)
    return ret


def hex2int(l):
    """
    convert hex list to int
    """
    ret = 0
    for i in l:
        ret = ret * 256 + i
    return ret


def prefix_len2len(prefix_len):
    """
    convert prefix len to prefix len field length
    """
    return int((prefix_len + 7) / 8)

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


# IP
def hex2ip(data, ip_version):
    if not ip_version in [4, 6]:
        raise ValueError(
            "ip_version should be 4 or 6,but get {}".format(ip_version))
    if ip_version == 4:
        full_len = 4
    elif ip_version == 6:
        full_len = 16
    while len(data) < full_len:
        data.append(0)
    ip_value = hex2int(data)
    return netaddr.IPAddress(ip_value)


def ip2hex(ip):
    if not isinstance(ip, netaddr.IPAddress):
        raise TypeError(
            "ip should be netaddr.IPAddress,but get {}".format(type(ip)))
    match ip.version:
        case 4:
            base = ip.packed.hex()
            base = [int(base[i:i+2], 16) for i in range(0, len(base), 2)]
            return base
        case 6:
            base = ip.network.packed.hex()
            base = [int(base[i:i+2], 16) for i in range(0, len(base), 2)]
            return base
        case _:
            raise ValueError(
                "ip_version should be 4 or 6,but get {}".format(ip.version))
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


def prefix2hex(prefix):
    """
    convert prefix to nlri (csv int)
    """
    match prefix.version:
        case 4:
            ip_address = list(prefix.ip.words)
            items = [prefix.prefixlen]
            items += ip_address[:int((int(prefix.prefixlen) + 7) / 8)]
            return items
        case 6:
            p_len = prefix.prefixlen
            items = [p_len]
            l = int((p_len+7)/8)
            items.extend(prefix.ip.packed[:l])
            return items
        case _:
            raise NotImplementedError


def hex2prefix(nlri, ip_version):
    if not ip_version in [4, 6]:
        raise ValueError(
            "ip_version should be 4 or 6,but get {}".format(ip_version))
    prefix_len = nlri[0]
    ip = hex2ip(nlri[1:], ip_version)
    return netaddr.IPNetwork(ip.format()+"/"+str(prefix_len))


def prefixes_to_hex_str(prefix_list, ip_type="ipv4"):
    """
        constructs NLRI prefix list
        :param prefix_list: prefix in str format list
    """
    if ip_type == "ipv4":
        items = []
        for prefix in prefix_list:
            items.extend(prefix2hex(prefix))
        return ",".join(items)
    else:
        raise NotImplementedError

# Path


def path2hex(asn_path, as4_session=True):
    """
        convert asn_path to hex
        :param asn_path: list of asn
        :return: hex value list (u8)
    """
    result = []
    if as4_session:

        for path in list(map(lambda x: int2hex(x, 4), asn_path)):
            result += path
    else:
        for path in list(map(lambda x: int2hex(x, 2), asn_path)):
            result += path
    return result


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


# SPA
def get_intra_spa_nlri_hex(origin_router_id, prefix, flag, miig_type=0, miig_tag=0):
    """
    get a intra-spa-nlri message in hex,
    length is calculated when converting to nlri
    flag: 0:source flag,1:destination flag
    """

    nlri = [
        1  # route type
    ]
    nlri.extend(int2hex(origin_router_id, 4))  # origin router id
    nlri.extend(prefix2hex(prefix))  # prefix
    nlri.append(miig_type)
    nlri.append(flag)
    nlri.extend(int2hex(miig_tag, 4))
    nlri.insert(1, len(nlri)-1)
    return nlri


def read_spa_sav_nlri(data, ip_version=6):
    result = []
    cur_pos = 0
    while cur_pos < len(data):

        route_type = data[cur_pos]
        cur_pos += 1
        length = data[cur_pos]
        cur_pos += 1
        # router id is ipv4,len is 4
        origin_router_id = hex2int(data[cur_pos:cur_pos+4])
        cur_pos += 4
        mask_len = prefix_len2len(data[cur_pos])
        prefix_hex = data[cur_pos:cur_pos+mask_len+1]
        cur_pos += mask_len+1
        prefix = hex2prefix(prefix_hex, ip_version)
        miig_type = data[cur_pos]
        cur_pos += 1
        flag = data[cur_pos]
        cur_pos += 1
        miig_tag = data[cur_pos:cur_pos+4]
        cur_pos += 4
        miig_tag = hex2int(miig_tag)
        nlri = {
            "route_type": route_type,
            "origin_router_id": origin_router_id,
            "prefix": prefix,
            "miig_type": miig_type,
            "flag": flag,
            "miig_tag": miig_tag
        }
        result.append(nlri)
    return result
# SPD


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
    return {"count": 0, "time": 0.0, "size": 0, "wait_time": 0.0}


def init_protocol_metric():
    return {"recv": init_direction_metric(),
            "send": init_direction_metric(),
            "start": None,
            "end": None}


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

# SAV Rule


def get_sav_rule(prefix, interface_name, source_app, origin=-1, is_interior=True):
    """
    return a tuple of sav rule elements
    if origin is not given, it will be set to -1
    by default, the origin is the origin as number(is_interior=True)
    otherwise, the origin is the origin router id(is_interior=False)
    """
    if not isinstance(prefix, netaddr.IPNetwork):
        raise TypeError(
            "prefix should be netaddr.IPNetwork,but get {}".format(type(prefix)))
    result = {
        "prefix": prefix,
        "interface_name": interface_name,
        "source_app": source_app,
        "origin": origin,
        "is_interior": is_interior
    }
    return result


def get_key_from_sav_rule(r):
    return f"{r['prefix']}_{r['origin']}_{r['interface_name']}"


def get_agent_bird_msg(data, msg_type, source_app, timeout, store_rep):
    "message from agent to bird"
    msg = {
        "data": data,
        "msg_type": msg_type,
        "source_app": source_app,
        "timeout": timeout,
        "store_rep": store_rep
    }
    return msg


def get_bird_spa_data(adds, dels, protocol_name,channel, rpdp_version, next_hop, as_path, is_as4):
    ret = {
        "add": adds,
        "add_len": len(adds),
        "del": dels,
        "del_len": len(dels),
        "type": "spa",
        "protocol_name": protocol_name,
        "is_native_bgp": False,
        "channel": channel,
        "rpdp_version": rpdp_version,
        "next_hop": next_hop,
        "as_path": [2, len(as_path)] + path2hex(as_path, is_as4)
        
    }
    ret["as_path_len"] = len(ret["as_path"])
    return ret


def get_bird_spd_data(protocol_name, channel, rpdp_version, sn, origin_id, opt_data, addresses):
    return {
        "type": "spd",
        "protocol_name": protocol_name,
        "is_native_bgp": False,
        "channel": channel,
        "rpdp_version": rpdp_version,
        "SN": sn,
        "origin_id": ip2hex(netaddr.IPAddress(origin_id)),
        "opt_data_len": len(opt_data),
        "opt_data": opt_data,
        "addresses": addresses
    }

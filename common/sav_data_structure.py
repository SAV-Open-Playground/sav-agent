#!/usr/bin/python3
# -*-coding:utf-8 -*-
"""
@File    :   data_structure.py
@Time    :   2023/08/08
@Version :   0.1
@Desc    :   Defines data structure and related conversions
"""
import netaddr
import time
import json
# for RPDP SPA msg

DEFAULT_MIIG_TYPE = 0
DEFAULT_MIIG_TAG = 0
ASN_TYPE = int
IP_ADDR_TYPE = netaddr.IPAddress
PREFIX_TYPE = netaddr.IPNetwork
TIMEIT_THRESHOLD = 0.5
LOG_FOR_FRONT_KEY_WORD = "LOG_FOR_FRONT"
BGP_UPDATE_DATA_MAX_LEN = 65516


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
    return netaddr.IPAddress(ip_value, ip_version)


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
            base = ip.packed.hex()
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


def prefixes2hex_str(prefix_list, ip_type="ipv4"):
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


def prefixes2addresses(prefix_list):
    """
    for spd msg
    """
    ret = []
    for p in prefix_list:
        ret.extend(prefix2hex(p))
    return ret


def addresses2prefixes(addresses, ip_version):
    """
    for spd msg
    """
    ret = []
    while len(addresses) > 0:
        prefix_len = addresses.pop(0)
        prefix_len2 = int((prefix_len+7)/8)
        prefix_hex = addresses[:prefix_len2]
        addresses = addresses[prefix_len2:]
        prefix_hex.insert(0, prefix_len)
        ret.append(hex2prefix(prefix_hex, ip_version))
    return ret


def ips2addresses(ip_list):
    """
    for spd msg
    """
    ret = []
    for ip in ip_list:
        ret.extend(ip2hex(ip))
    return ret


def addresses2ips(addresses, ip_version):
    """
    for spd msg
    """
    ret = []
    if ip_version == 4:
        while len(addresses) > 0:
            ret.append(hex2ip(addresses[:4], ip_version))
            addresses = addresses[4:]
    elif ip_version == 6:
        while len(addresses) > 0:
            ret.append(hex2ip(addresses[:16], ip_version))
            addresses = addresses[16:]
    else:
        raise ValueError(
            "ip_version should be 4 or 6,but get {}".format(ip_version))
    return ret
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


def path2as_path(path, as4_session):
    """
    convert path to as_path
    """
    result = []
    for asn in path:
        result.append(2)
        result.append(1)
        if as4_session:
            result += int2hex(asn, 4)
        else:
            result += int2hex(asn, 2)
    return result


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


def get_inter_spa_nlri_hex(origin_asn, prefix, flag):
    """
    get a inter-spa-nlri message in hex,
    missing miig_type and miig_tag compared with intra-spa-nlri
    """
    nlri = [
        2  # route type
    ]
    nlri.extend(int2hex(origin_asn, 4))  # origin router id
    nlri.extend(prefix2hex(prefix))  # prefix
    nlri.append(flag)
    nlri.insert(1, len(nlri)-1)
    return nlri


def read_intra_spa_nlri_hex(data, ip_version):
    result = []
    cur_pos = 0
    # input(data)
    while cur_pos < len(data):
        nlri = {}
        route_type = data[cur_pos]
        nlri["route_type"] = route_type
        cur_pos += 1
        length = data[cur_pos]
        # input(data[cur_pos:cur_pos+length])
        cur_pos += 1
        # router id is ipv4,len is 4
        origin_router_id = netaddr.IPAddress(
            hex2int(data[cur_pos:cur_pos+4]), 4)
        nlri["origin_router_id"] = origin_router_id
        # print(nlri)
        cur_pos += 4
        # input(data[cur_pos])
        mask_len = prefix_len2len(data[cur_pos])
        # input(mask_len)
        prefix_hex = data[cur_pos:cur_pos+mask_len+1]
        cur_pos += mask_len+1
        # input(prefix_hex)
        prefix = hex2prefix(prefix_hex, ip_version)
        nlri["prefix"] = prefix
        miig_type = data[cur_pos]
        nlri["miig_type"] = miig_type
        cur_pos += 1
        flag = data[cur_pos]
        nlri["flag"] = flag
        cur_pos += 1
        miig_tag = data[cur_pos:cur_pos+4]
        cur_pos += 4
        miig_tag = hex2int(miig_tag)
        nlri["miig_tag"] = miig_tag
        result.append(nlri)
    return result


def read_inter_spa_nlri_hex(data, ip_version):
    """
    read inter spa data from hex
    """

    result = []
    cur_pos = 0
    while cur_pos < len(data):
        nlri = {}
        route_type = data[cur_pos]
        nlri["route_type"] = route_type
        cur_pos += 1
        length = data[cur_pos]
        cur_pos += 1
        # router_id len is 4
        nlri["origin_asn"] = hex2int(data[cur_pos:cur_pos+4])
        print(data[cur_pos:cur_pos+4])
        cur_pos += 4
        mask_len = prefix_len2len(data[cur_pos])
        prefix_hex = data[cur_pos:cur_pos+mask_len+1]
        cur_pos += mask_len+1
        prefix = hex2prefix(prefix_hex, ip_version)
        nlri["prefix"] = prefix
        flag = data[cur_pos]
        nlri["flag"] = flag
        cur_pos += 1
        result.append(nlri)
    return result


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
    reverse of prefixes2hex_str
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

# SAV Rule & Table


def get_sav_rule(prefix, interface_name, source_app, origin=-1, is_interior=True):
    """
    return a dict of sav rule elements
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
    """
    return a string key for sav rule
    """
    return f"{r['prefix']}_{r['origin']}_{r['interface_name']}"


def rule_dict_diff(old_rules, new_rules):
    """
    return adds and dels for the given dicts
    remember to del first and then add (updates)
    """
    adds = {}
    dels = set()
    for key in new_rules:
        if key not in old_rules:
            adds[key] = new_rules[key]
        else:
            new_rules[key]["create_time"] = old_rules[key]["create_time"]
            new_rules[key]["update_time"] = old_rules[key]["update_time"]
            if new_rules[key] != old_rules[key]:
                adds[key] = new_rules[key]
                new_rules[key]["update_time"] = time.time()
                dels.add(key)
    for key in old_rules:
        if key not in new_rules:
            dels.add(key)
    return adds, dels


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


def get_bird_spa_data(adds, dels, protocol_name, channel, rpdp_version, next_hop, as_path, is_as4, is_interior):
    """
    return a dict of spa data for bird
    """
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
        "origin": [1, 0],  # intra value
        "is_interior": 0
    }
    if is_interior:
        ret["origin"] = path2hex([as_path[0]], is_as4)
        # ret["as_path"] = [2, len(as_path)] + path2hex(as_path, is_as4)
        ret["as_path"] = path2as_path(as_path, is_as4)
        ret["sav_path"] = path2hex(as_path, is_as4)
        ret["sav_path_len"] = len(ret["sav_path"])
        ret["as_path_len"] = len(ret["as_path"])
        ret["is_interior"] = 1
    return ret


def get_bird_spd_data(protocol_name, channel, rpdp_version, sn, origin_router_id, opt_data,  is_interior, addresses=[], my_as=-1, peer_as=-1, peer_neighbor_as_list=None):
    """
    return a dict of spd data for bird
    all optional parameters are for special for inter spd or intar spd.
    @param protocol_name:  link_name
    @param channel:  channel (rpdp)
    @param rpdp_version:  rpdp version (4)
    @param sn:  sequence number
    @param origin_router_id:  origin router id
    @param opt_data:  optional data
    @param addresses:  addresses
    """

    addresses = ips2addresses(addresses)
    ret = {
        "type": "spd",
        "protocol_name": protocol_name,
        "is_native_bgp": False,
        "channel": f"{channel}{rpdp_version}",
        "rpdp_version": rpdp_version,
        "SN": sn,
        "origin_router_id": ip2hex(netaddr.IPAddress(origin_router_id)),
        "opt_data_len": len(opt_data),
        "opt_data": opt_data,
        "addresses": addresses, "is_interior": 0
    }
    if is_interior:
        ret["is_interior"] = 1
        if my_as == -1 or peer_as == -1:
            raise ValueError("my_as or peer_as is not given")
        if peer_neighbor_as_list == None:
            raise ValueError("peer_neighbor_as_list not given")
        ret["source_asn"] = my_as
        ret["validate_asn"] = peer_as
        ret["neighbor_ases"] = []
        for asn in peer_neighbor_as_list:
            ret["neighbor_ases"].append(int2hex(asn))
    return ret
# TestCase


def test_prefix2hex():
    test_p = netaddr.IPNetwork("1.1.1.0/24")
    a = prefix2hex(test_p)
    assert test_p == hex2prefix(a, 4)


def test_spa():

    # a = get_inter_spa_nlri_hex(65501, netaddr.IPNetwork("192.168.1.0/24"), 0)
    # print(a)
    # print(read_inter_spa_nlri_hex(a, 4))
    # b = get_inter_spa_nlri_hex(65501, netaddr.IPNetwork("feb::1:1/128"), 0)
    # print(b)
    # print(read_inter_spa_nlri_hex(b, 6))
    # testing_tiner_spa_v6= [2, 21, 0, 0, 255, 222, 120, 15, 235, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 3, 0, 0, 2, 14, 0, 0, 255, 222, 64, 254, 128, 0, 0, 0, 0, 0, 0, 0, 2, 22, 0, 0, 255, 222, 128, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 2, 22, 0, 0, 255, 222, 128, 254, 128, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2, 22, 0, 0, 255, 222, 128, 254, 128, 0, 0, 0, 0, 0, 0, 48, 67, 87, 255, 254, 125, 94, 33, 0, 2, 22, 0, 0, 255, 222, 128, 254, 128, 0, 0, 0, 0, 0, 0, 148, 220, 175, 255, 254, 246, 14, 53, 0, 2, 7, 0, 0, 255, 222, 8, 255, 0]
    # input(get_intra_spa_nlri_hex(netaddr.IPAddress("1.1.1.1",4),netaddr.IPNetwork("feb::1:1/128"),0,0,0))
    testing_intra_spa_v6 = [1, 0, 1, 26, 0, 3, 0, 1, 120, 15, 235, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 3, 0, 1, 0, 0, 0, 0, 0, 1, 19, 0, 3, 0, 1, 64, 254, 128, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 27, 0, 3, 0, 1, 128, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 1, 27, 0, 3, 0, 1, 128, 254, 128, 0,
                            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 27, 0, 3, 0, 1, 128, 254, 128, 0, 0, 0, 0, 0, 0, 20, 182, 164, 255, 254, 113, 18, 247, 0, 0, 0, 0, 0, 0, 1, 27, 0, 3, 0, 1, 128, 254, 128, 0, 0, 0, 0, 0, 0, 48, 67, 87, 255, 254, 125, 94, 33, 0, 0, 0, 0, 0, 0, 1, 12, 0, 3, 0, 1, 8, 255, 0, 0, 0, 0, 0, 0]
    print(read_intra_spa_nlri_hex(testing_intra_spa_v6, 6))
# print(read_spa_sav_nlri([1, 14, 192, 168, 3, 1, 24, 192, 168, 2, 1, 0, 0, 0,
#       0, 1, 1, 14, 192, 168, 3, 1, 24, 192, 168, 3, 1, 0, 0, 0, 0, 1], 4))

# print(hex2int([0, 0, 255, 222]))


# BIRD CLI OUTPUT PARSING
def my_split(str_data, split_char):
    """
    split string with split_char
    """
    ret = str_data.split(split_char)
    while "" in ret:
        ret.remove("")
    return ret


def process_src_kv(k, v, my_asn):
    """
    add values to each source identified
    """
    k_temp = k.split()
    if '*' in k_temp:
        k_temp.remove('*')
    v["broadcast_type"] = k_temp[0]
    if not k_temp[1].startswith("["):
        print(k_temp)
        raise ValueError("unknown key")
    v["protocol_name"] = k_temp[1][1:]
    if not k_temp[2].endswith("]"):
        print(k_temp)
        raise ValueError("unknown key")
    v["time"] = k_temp[2][:-1]
    k_l = len(k_temp)

    if not (k_temp[3].startswith("(") and k_temp[3].endswith(")")):
        print(k_temp)
        raise ValueError("unknown metric")
    m1 = int(k_temp[3][1:-1])
    if "metric" in v:
        if v["metric"] != m1:
            print(k_temp)
            print(v)
            raise ValueError("metric not match")
    v["metric"] = m1
    if k_l == 4:
        return v
    elif k_l == 5:
        if k_temp[4] == "[i]":
            v["origin_asn"] = my_asn
            return v
        if not (k_temp[4].startswith("[AS") and k_temp[4].endswith("i]")):

            raise ValueError(f"unknown AS :{k_temp}")

        v["origin_asn"] = int(k_temp[4][3:-2])
        return v
    else:
        raise ValueError(f"unknown key:{k_temp}")
    return 1


def parse_prefix(data, my_asn):
    """
    special parsing for bird show route all cmd,
    not fully tested
    """
    lines = my_split(data, "\n")
    ret = {}
    cur_prefix = None
    for i in lines:
        while "  " in i:
            i = i.replace("  ", " ")
        if i.startswith("\t"):
            if cur_prefix == None:
                raise ValueError("prefix not found")
            ret[cur_prefix].append(i)
        elif i.startswith(" "):
            ret[cur_prefix].append(i)
        else:
            temp = my_split(i, " ")
            prefix = temp[0]
            prefix = netaddr.IPNetwork(prefix)
            ret[prefix] = [" "+" ".join(temp[1:])]
            cur_prefix = prefix
    hardcoded_keys = {"\tdev ": "device",
                      "\tType: ": "type",
                      "\tBGP.origin: ": "origin",
                      "\tBGP.as_path: ": "as_path",
                      "\tvia ": "via",
                      "\tBGP.next_hop: ": "next_hop",
                      "\tBGP.local_pref: ": "metric",
                      "\tBGP.otc: ": "only_to_customer",
                      "\tBGP.community: ": "community",
                      "\tKernel.source: ": "kernel_source",
                      "\tKernel.metric: ": "Kernel_metric"}
    for prefix, lines in ret.items():
        srcs = {}
        cur_key = None
        for l in lines:
            if l.startswith(" "):
                cur_key = l[1:]
                srcs[cur_key] = {}
            else:
                if cur_key == None:
                    raise ValueError("key not found")
                found = False
                # input(l)
                for k, v in hardcoded_keys.items():
                    if l.startswith(k):
                        srcs[cur_key][v] = l[len(k):]
                        if k == "\tBGP.as_path: ":
                            srcs[cur_key][v] = list(
                                map(int, srcs[cur_key][v].split()))
                            if len(srcs[cur_key][v]) > 0:
                                srcs[cur_key]["origin"] = srcs[cur_key][v][0]
                                srcs[cur_key]["origin_type"] = "AS"
                        elif k == "\tBGP.local_pref: ":
                            srcs[cur_key][v] = int(
                                srcs[cur_key][v])
                        elif k == "\tvia ":
                            srcs[cur_key]["interface_name"] = l.split("on ")[1]
                        found = True
                        break
                if not found:
                    print(data)
                    raise ValueError(f"unknown key {[l]}")
        new_srcs = []
        for k, v in srcs.items():
            new_v = process_src_kv(k, v, my_asn)
            if new_v is None:
                print(k)
                print(v)
                raise ValueError("new_v is None")
            new_srcs.append(new_v)
        ret[prefix] = new_srcs
        #         if len(k_temp) == 4:
        #             # print(k_temp)
        #             v["broadcast_type"] = k_temp[0]
        #             v["link_name"] = k_temp[1][1:]
        #             v["time"] = k_temp[2][:-1]
        #             m1 = int(k_temp[3][1:-1])
        #             if "metric" in v:
        #                 if v["metric"] != m1:
        #                     print(k_temp)
        #                     print(v)
        #                     raise ValueError("metric not match")
        #             else:
        #                 v["metric"] = m1
        #             new_srcs.append( v)
        #         else:
        #             print(k_temp)
        #             raise ValueError("unknown key")
        #     elif v["type"] == "static univ":
        #         print(k,v)
        #     else:
        #         print(v["type"])
        #         print(k)
        #         print(v)
        # ret[prefix] = temp
    return ret


def parse_r4(data):
    """
    parse bird roa table
    return a dict of {asn:[prefix]}
    """
    lines = my_split(data, "\n")
    ret = {}
    i = 0
    while i < len(lines):
        l = lines[i]
        temp = my_split(l, " ")
        prefix = temp[0].split("-")[0]
        asn = int(temp[1][2:])
        if not asn in ret:
            ret[asn] = []
        ret[asn].append(prefix)
        if lines[i+1].startswith("\t"):
            i += 1
        i += 1
    return ret


def parse_bird_show_route_all(data, my_asn):
    """parse the out put of bird show route all cmd"""
    tables = my_split(data, "Table")
    ret = {}
    for i in tables:
        lines = my_split(i, "\n")
        table_heading = lines.pop(0)
        table_name = table_heading.strip().split(":")[0]

        table_data = i.split(table_heading)[1][1:]
        if table_name == "r4":
            ret[table_name] = parse_r4(table_data)
        elif table_name == "r6":
            raise NotImplementedError
        else:
            ret[table_name] = parse_prefix(table_data, my_asn)
    return ret

# test_spa()

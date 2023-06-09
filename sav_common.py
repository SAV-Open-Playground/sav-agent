#!/usr/bin/python3
# -*- encoding: utf-8 -*-
"""
@Time    :   2023/01/17 16:04:22
common functions and classes for sav
"""
import json
import os
import time
import logging
import logging.handlers
import netaddr
import requests


# AS number int
# IP Address 
# Network netaddr class
# =============================== start_of_key_words ==========================================
def is_asn(in_put):
    if isinstance(in_put,int):
        pass 
    #TODO
class RPDPPeer():
    def __init__(self,asn,port,ip,is_as4) -> None:
        self.asn = asn
        self.port = port
        self.ip = ip
        self.is_as4 = is_as4
    def __str__(self) -> str:
        return f"{self.asn},{self.ip}:{self.ip}"
ASN_TYPE = int
IP_ADDR_TYPE = netaddr.IPAddress
PREFIX_TYPE = netaddr.IPNetwork
RPDP_PEER_TYPE = RPDPPeer

def parse_bird_table(table, logger=None):
    """
        return table_name(string) and parsed_rows(dict)
        """
    # logger.debug(table)
    temp = table.split("\n")
    while "" in temp:
        temp.remove("")
    table_name = temp[0][1:-1]
    parsed_rows = {}
    temp = temp[1:]
    rows = []
    this_row = []
    for line in temp:
        if (line.startswith("\t") or line.startswith(" ")):
            this_row.append(line)
        else:
            rows.append(this_row)
            this_row = [line]
    while [] in rows:
        rows.remove([])
    # logger.debug(rows)
    for row in rows:
        heading = row.pop(0)
        # skip blackhole
        if "blackhole" in heading:
            continue
        prefix = heading.split(" ")[0]
        prefix = prefix.replace("24-24", "24")
        # TODO: demo filter
        if not prefix.startswith("192"):
            continue
        prefix = netaddr.IPNetwork(prefix)
        if prefix not in parsed_rows:
            parsed_rows[prefix] = []
        temp = {}
        for line in row:
            if line.startswith("\tBGP.as_path: "):
                temp["as_path"] = list(
                    map(int, line.split(": ")[1].split(" ")))
                temp["as_path"].reverse()
                temp["origin_as"] = temp["as_path"][0]
            if line.startswith("\tvia"):
                temp["interface_name"] = line.split("on ")[-1]
                temp["interface_ip"] = line.split(
                    "on ")[0].split("via ")[-1]
            if line.startswith("                     "):
                parsed_rows[prefix].append(temp)
                temp = {}
        parsed_rows[prefix].append(temp)
        # parsed_rows[prefix].sort()
    return table_name, parsed_rows


def rule_list_diff(old_rules, new_rules):
    """
    return adds and dels for the given lists
    """
    adds_ = []
    dels_ = []
    for item in new_rules:
        if item not in old_rules:
            adds_.append(item)
    for item in old_rules:
        if item not in new_rules:
            dels_.append(item)
    return adds_, dels_


def decode_csv(input_str):
    """
    return a list of strings
    """
    if input_str == "":
        return []
    if "," in input_str:
        return input_str.split(",")

    return [input_str]


def sav_rule_tuple(prefix, interface_name, rule_source, as_number=-1):
    """
    return a tuple of sav rule elements
    """
    if not isinstance(prefix, str):
        prefix = str(prefix)
    return (prefix, interface_name, rule_source, as_number)


def get_logger(file_name):
    """
    get logger function for all modules
    """
    maxsize = 1024*1024*500
    backup_num = 5

    logger = logging.getLogger(__name__)
    logger.setLevel(logging.DEBUG)
    handler = logging.handlers.RotatingFileHandler(os.path.dirname(os.path.abspath(
        __file__))+f"/../logs/{file_name}.log", maxBytes=maxsize, backupCount=backup_num)
    handler.setLevel(logging.DEBUG)

    formatter = logging.Formatter(
        # "[%(asctime)s] [%(process)d] [%(filename)s] [%(funcName)s] [%(levelname)s] %(message)s")
        "[%(asctime)s]  [%(filename)s:%(lineno)s-%(funcName)s] [%(levelname)s] %(message)s")
    formatter.converter = time.gmtime
    handler.setFormatter(formatter)

    logger.addHandler(handler)
    return logger


def tell_str_is_interior(input_str):
    """
    tell the given str contains as_number or ip
    return True if AS number detected.
    return False if ip detected.
    """
    if len(input_str) == 0:
        raise ValueError("empty string")
    if "," in input_str:
        input_str = input_str.split(",")
    else:
        input_str = [input_str]
    while "" in input_str:
        input_str.remove("")
    try:
        map(int, input_str)
        return True
    except ValueError:
        pass
    try:
        map(netaddr.IPAddress, input_str)
        return False
    except:
        raise ValueError("invalid string: " + input_str)


def ln(list_of_interface):
    """
    return a a list of protocol_names
    """
    result = []
    for i in list_of_interface:
        result.append(i["meta"]["protocol_name"])
    return result


def asn_to_hex(asn, as_session=False):
    """
        convert asn to hex
        :param asn: asn
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


def path_to_hex(asn_path, as4_session=False):
    """
        convert asn_path to hex
        :param asn_path: list of asn
        :return: hex value list (u8)
    """
    result = []
    for path in list(map(lambda x: asn_to_hex(x, as4_session), asn_path)):
        result += path
    return result


def get_kv_match(list_of_dict, key, value):
    result = []
    for data_dict in list_of_dict:
        if data_dict[key] == value:
            result.append(data_dict)
    return result


def ipv4_str_to_hex(ip_str):
    """
        convert ipv4 to hex
        :param ipv4: ipv4 address
        :return: hex value list (u8)
    """
    return ip_str.split(".")


def scope_to_hex_str(scope, is_inter, is_as4=True):
    temp = [str(len(scope))]
    if is_inter:
        for path in scope:
            temp.append(str(len(path)))
            temp += path_to_hex(path, is_as4)
        return ",".join(temp)

    for path in scope:
        temp.append(str(len(path)))
        for ipv4 in path:
            temp += ipv4_str_to_hex(ipv4)
    return ",".join(temp)


def read_json(path_to_json):
    with open(path_to_json, "r", encoding="utf-8") as json_file:
        return json.loads(json_file.read())


def save_json(path_to_json, json_obj):
    with open(path_to_json, "w", encoding="utf-8") as json_file:
        json_file.write(json.dumps(json_obj, indent=4))


class InfoManager():
    """
    info manager manage the info of stored data,
    base class for SavAgent and SavApp.
    """
    def __init__(self, data, logger):
        self.logger = logger
        self.data = data
        if not isinstance(self.data, dict):
            raise ValueError("data is not a dictionary")
    def __init__(self, data, logger):
        self.logger = logger
        self.data = data
        if not isinstance(self.data, dict):
            raise ValueError("data is not a dictionary")

    def add(self, msg):
        raise NotImplementedError

    def delete(self, key):
        raise NotImplementedError

    def get(self, key):
        raise NotImplementedError

    def update(self, key, value):
        raise NotImplementedError

    def add_update(self, key, value):
        raise NotImplementedError

    def is_up(self, key):
        raise NotImplementedError

    def get_all(self):
        raise NotImplementedError

    def get_all_up(self):
        raise NotImplementedError


class SavApp():
    """
    SavApp class helps receive and send massage using links
    SavAgent do not detect the link status,
    it is the app"s responsibility to manipulate the link status.
    one app can manage multiple links
    app manage the links status by inserting update msg
    """

    def __init__(self, agent, name, logger=None):
        if not logger:
            logger = get_logger(name)
        self.logger = logger
        self.status = True
        self.name = name
        self.agent = agent

    def is_up(self):
        return self.status is True

    def send_msg(self, msg):
        raise NotImplementedError

    def recv_msg(self):
        raise NotImplementedError

    def check_status(self):
        raise NotImplementedError

    def fib_changed(self):
        raise NotImplementedError

    def put_link_up(self, link_name,link_type):
        # this msg may incur creating of new link, so we need to know the type
        msg = {
            "msg_type": "link_state_change",
            "source_app": self.name,
            "source_link": link_name,
            "link_type": link_type,
            "msg": True,
        }
        self.agent.put_msg(msg)
    def set_link_type(self,link_name, link_type):
        # this msg may incur creating of new link, so we need to know the type
        msg = {
            "msg_type": "set_link_type",
            "source_app": self.name,
            "source_link": link_name,
            "msg": link_type,
        }
        self.agent.put_msg(msg)

    def put_link_down(self, link_name):
        msg = {
            "msg_type": "link_state_change",
            "source_app": self.name,
            "source_link": link_name,
            "msg": False
        }
        self.agent.put_msg(msg)

# class Link():
#     """
#     the intermedia between two sav agents
#     """
    # def __init__(self,link_name,source_app,remote_addr,remote_as,local_addr,local_as,interface,type):
class LinkManager(InfoManager):
    """
    LinkManager manage the link status
    """
# TODO: we have three types of link: native bgp, modified bgp and grpc
    def add(self, link_name, link_dict,link_type):
        if "rpki" in link_name:
            return
        self.logger.debug(f"adding {link_name},{link_dict}")
        if link_name in self.data:
            self.logger.warning(f"key {link_name} already exists")
            return
        if not link_type in ["native_bgp", "modified_bgp","grpc"]:
            self.logger.error(f'unknown link_type: {link_type}')
        link_dict["link_type"] = link_type
        self.data[link_name] = link_dict

    def add_meta(self, link_name, meta):
        old_meta = self.data[link_name]["meta"]
        if len(old_meta) != 0:
            if list(old_meta.keys()) != list(meta.keys()):
                self.logger.warning(
                    "meta conflict !\n old meta: {old_meta}\n new met: {meta}")
                return
            if old_meta != meta:
                self.logger.warning(
                    "meta conflict !\n old meta: {old_meta}\n new met: {meta}")
                return
            return
        if link_name in self.data:
            self.data[link_name]["meta"] = meta
        # self.db.upsert("link", json.dumps(self.data))

    def get(self, key):
        return self.data[key]

    def get_by(self, remote_as, is_interior):
        """return a list of link objects that matches both remote_as,is_interior
            return None if not found
        """
        result = []
        for key in self.data:
            link = self.data[key]
            if (link["meta"]["remote_as"] == remote_as) and (
                    link["meta"]["is_interior"] == is_interior):
                result.append(link)
        return result

    def get_all_up(self,include_native_bgp = False):
        """
        return a list of all up link_names ,use get(link_name) to get link object
        """
        temp = []
        for link_name in self.data:
            link = self.data[link_name]
            if link["status"]:
                if link["link_type"] == "native_bgp":
                        if include_native_bgp:
                            temp.append(link_name)
                else:
                    temp.append(link_name)
        return temp

    def get_all_up_type(self, is_interior,include_native_bgp = False):
        """
        return a list of all up link_names with the correct type (is_interior or not),
        use get(link_name) to get link object
        """
        result = []
        for link_name in self.get_all_up(include_native_bgp):
            if self.data[link_name]["meta"]["is_interior"] == is_interior:
                result.append(link_name)
        return result

    def exist(self, link_name):
        return link_name in self.data

def get_agent_app_msg(link_meta, msg_meta, logger):
    """
    message between agent and app
    """
    # self.as4_session = link_meta["as4_session"]
    # self.protocol_name = link_meta["protocol_name"]
    if not isinstance(msg_meta["is_interior"], bool):
        raise ValueError("is_interior type error,   ")
    if not isinstance(link_meta["src"], str):
        raise ValueError("src type error, should be a string")
    if not isinstance(link_meta["dst"], str):
        raise ValueError("dst type error, should be a string")
    if not isinstance(msg_meta["scope"], list):
        raise ValueError("scope type error, should be a list")
    if not isinstance(msg_meta["nlri"], list):
        raise ValueError("nlri type error, should be a list")
    if not isinstance(msg_meta["path"], list):
        logger.error(msg_meta["path"])
        logger.error(type(msg_meta["path"]))
        raise ValueError("path type error, should be a list")
    if not isinstance(msg_meta["origin"], str):
        raise ValueError("origin type error")
    if msg_meta["is_interior"]:
        if not tell_str_is_interior(msg_meta["path"]) or\
                not tell_str_is_interior(msg_meta["origin"]):
            raise ValueError(
                "interior msg should have interior path and origin")
    for path in msg_meta["scope"]:
        if not tell_str_is_interior(path):
            raise ValueError(
                "interior msg should have interior scope")
            
def prefixes_to_hex_str(prefix_list, ip_type="ipv4"):
    """
        constructs NLRI prefix list
        :param prefix_list: prefix in str format list
    """
    if ip_type == "ipv4":
        items = []
        for prefix in prefix_list:
            prefix = str(prefix)
            ip_address, prefix = prefix.split("/")
            items.append(prefix)
            ip_address = ip_address.split(".")
            items += ip_address[:int((int(prefix) + 7) / 8)]
        return ",".join(items)
    else:
        raise NotImplementedError
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
    
def str_to_scope(input_str):
    temp = decode_csv(input_str)
    result = []
    while len(temp) > 0:
        scope_len = int(temp.pop(0))
        for _ in range(scope_len):
            path_len = int(temp.pop(0))
            path = []
            for _ in range(path_len):
                path.append(temp.pop(0))
            result.append(path)
    return result
def remove_local(list_of_fib):
    """
    remove local prefixes
    """
    return [i for i in list_of_fib if not '0.0.0.0' in i['Gateway']]

def get_aspa(logger, hostname, port_number, pwd="krill"):
    while True:
        try:
            headers = {"Authorization": f"Bearer {pwd}",
                       "Content-Type": "application/json"}
            url = f"https://{hostname}:{port_number}/api/v1/cas/testbed/aspas"
            response = requests.request(
                "GET", url, headers=headers, verify=False)
            response.raise_for_status()  # Raises an exception for any HTTP error status codes
            # Return the response as a dictionary
            return response.json()
        except Exception as err:
            logger.debug(err)
            time.sleep(0.1)


def aspa_check(meta, aspa_info):
    """
    return True if the meta is in the aspa_info
    """
    # TODO: ipv6
    adj_provider_as = f"AS{meta['meta']['local_as']}(v4)"
    adj_customer_as = meta["meta"]["remote_as"]
    for data in aspa_info:
        if data["customer"] == int(adj_customer_as):
            return adj_provider_as in data["providers"]
    return False

def check_agent_agent_msg(msg, logger):
    """
    message structure between agent and agent,
    there are two types :'origin' and 'relay'
    """
    # self.as4_session = link_meta["as4_session"]
    # self.protocol_name = link_meta["protocol_name"]
    # check src dst
    # raise an error if the given msg is not a valid agent to agent message
    origin_key = "sav_origin"
    path_key = "sav_path"
    # logger.debug(json.dumps(msg,indent=2))
    if not isinstance(msg["src"], str):
        raise TypeError("src type error, should be a string")
    if not isinstance(msg["dst"], str):
        raise TypeError("dst type error, should be a string")
    if not msg["msg_type"] in ['origin','relay']:
        raise ValueError(f"mst_type should be ether 'origin' or 'relay'")

    if not isinstance(msg["sav_scope"], list):
        raise TypeError("scope type error, should be a list")
    if not isinstance(msg["sav_nlri"], list):
        raise TypeError("sav_nlri type error, should be a list")
    
    if not isinstance(msg[path_key], list):
        raise TypeError("path type error, should be a list")
    for path in msg[path_key]:
        if not tell_str_is_interior(path):
            logger.debug(msg[path_key])
            logger.debug(path)
            raise ValueError(f"{path_key} should contain path value")
    
    if not isinstance(msg[origin_key], str):
        raise TypeError(f"{origin_key} type error")
    
    if not isinstance(msg["is_interior"], bool):
        raise TypeError("is_interior type error, should be bool")
    if msg["is_interior"]:
        if not tell_str_is_interior(msg[origin_key]):
            raise ValueError(
                "interior msg should have interior path and origin")

    return True



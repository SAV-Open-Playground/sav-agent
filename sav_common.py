#!/usr/bin/python3
# -*-coding:utf-8 -*-
"""
@File    :   sav_common.py
@Time    :   2023/01/17 16:04:22
@Author  :   Yuqian Shi
@Version :   0.1

@Desc    :   The sav_common.py contains shared functions and classes
"""

import json
import os
import time
import logging
import logging.handlers
import netaddr
import requests
import subprocess


from sav_data_structure import *

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
            if line.startswith("\tBGP.as_path:"):
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
        if len(parsed_rows[prefix])==1 and len(parsed_rows[prefix][0])==0:
            del parsed_rows[prefix]
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

def run_cmd(command,shell=True, capture_output=True, encoding='utf-8'):
    return subprocess.run(command, shell=shell, capture_output=capture_output, encoding=encoding)

def keys_types_check(d,key_types):
    """
    raise KeyError if key is missing
    raise TypeError if key is not the right type
    """
    for k, t in key_types:
        if not k in d:
            raise KeyError(f"{k} missing in {d}")
        if not isinstance(d[k],t):
            raise TypeError(f"{k} should be {t} but {type(d[k])} found")

def get_host_interface_list():
    """
    return a list of 'clean' interface names
    """
    command = "ip link|grep -v 'link' | grep -v -E 'docker0|lo' | awk -F: '{ print $2 }' | sed 's/ //g'"
    command_result = run_cmd(command=command)
    std_out = command_result.stdout
    result = std_out.split("\n")[:-1]
    result = list(map(lambda x: x.split('@')[0], result))
    return [i for i in result if len(i) != 0]

def get_logger(file_name):
    """
    get logger function for all modules
    """
    maxsize = 1024*1024*500
    backup_num = 5
    level = logging.WARN
    level = logging.DEBUG
    logger = logging.getLogger(__name__)
    logger.setLevel(level)
    handler = logging.handlers.RotatingFileHandler(os.path.dirname(os.path.abspath(
        __file__))+f"/../logs/{file_name}.log", maxBytes=maxsize, backupCount=backup_num)
    handler.setLevel(level)

    formatter = logging.Formatter("[%(asctime)s]  [%(filename)s:%(lineno)s-%(funcName)s] [%(levelname)s] %(message)s")
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
            temp += path2hex(path, is_as4)
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
    def _bird_cmd(self, cmd):
        return birdc_cmd(self.logger,cmd)
    def _parse_roa_table(self,t_name = 'r4'):
        return get_roa(self.logger,t_name)
def birdc_cmd(logger, cmd):
        """
        execute bird command and return the output in std
        """
        proc = subprocess.Popen(
            ["/usr/local/sbin/birdc "+cmd],
            shell=True,
            stdout=subprocess.PIPE,
            stdin=subprocess.PIPE,
            stderr=subprocess.PIPE)
        proc.stdin.write("\n".encode("utf-8"))
        proc.stdin.flush()
        proc.wait()
        out = proc.stdout.read().decode()
        temp = out.split("\n")[0]
        temp = temp.split()
        if len(temp) < 2:
            return None
        if not (temp[0] == "BIRD" and temp[-1] == "ready."):
            logger.error(f"birdc execute error:{out}")
            return None
        out = "\n".join(out.split("\n")[1:])
        return out
def birdc_show_protocols(logger):
    """
    execute show protocols 
    """
    data = birdc_cmd(logger,cmd="show protocols")
    if data is None:
        return {}
    data = data.split("\n")
    while "" in data:
        data.remove("")
    return data
def birdc_get_protos_by(logger,key,value):
    data = birdc_show_protocols(logger)
    title = data.pop(0).split()
    result = []
    for row in data:
        temp = row.split()
        a = {}
        for i in range(min(len(title),len(temp))):
            a[title[i]]=temp[i]
        if not key in a:
            logger.error(f"key {key} missing in:{list(a.keys())}")
            return result
        if a[key]==value:
            result.append(a)
    return result
def birdc_get_import(logger, protocol_name, channel_name="ipv4"):
        """
        using birdc show all import to get bird fib
        return a list
        """
        cmd = f"show route all import table {protocol_name}.{channel_name}"
        data = birdc_cmd(logger,cmd)
        if data.startswith("No import table in channel"):
            logger.warning(data[:-1])
            return {"import": {}}
        if data is None:
            return {"import": {}}
        data = data.split("Table")
        while "" in data:
            data.remove("")
        for table in data:
            table_name, table_data = parse_bird_table(table, logger)
            if table_name =="import":
                return table_data
        return []
def get_roa(logger,t_name= 'r4'):
    """
    get ROA info from bird table
    """
    cmd = "show route table "+t_name
    row_str = []
    # detect if roa table have rows and stale
    last_len = -1
    for _ in range(30):
        data = birdc_cmd(logger,cmd)
        if data is None:
            logger.warning('empty roa')
            return {}
        row_str = data.split("\n")[1:]
        while "" in row_str:
            row_str.remove("")
        this_len = len(row_str)
        if this_len > 0:
            if this_len == last_len:
                break
            else:
                last_len = this_len
        time.sleep(0.1)
    if len(row_str) == 0:
        logger.warning("no roa info detected")
        return {}
    else:
        result = {}
        for row in row_str:
            d = row.split(" ")
            as_number = int(d[1][2:])
            prefix = d[0]
            prefix = prefix.replace('24-24', '24')
            if as_number not in result:
                result[as_number] = []
            result[as_number].append(netaddr.IPNetwork(prefix))
            # result[as_number].append(prefix)
    return result
def get_p_by_asn(asn,roa,aspa):
    """
    return a a dict(key is prefix,value is origin as) of unique prefix that could be used as src in packet from this as using aspa an roa info
    customer and peer is considered
    """
    result = {}
    for p in roa[asn]:
        result[p] = asn
    added = True
    ass = [asn]
    while added:
        added = False
        for customer_asn,providers in aspa.items(): 
            if element_exist_check(ass,providers):
                if not customer_asn in ass:
                    ass.append(customer_asn)
                    for p in roa[customer_asn]:
                        if not p in result:
                            result[p]=customer_asn
                    added = True
    return result                    
def element_exist_check(a,b):
    """
    return True if any element in a exists in b
    """
    for e in a:
        if e in b:
            return True
    return False
# class Link():
#     """
#     the intermedia between two sav agents
#     """
    # def __init__(self,link_name,source_app,remote_addr,remote_as,local_addr,local_as,interface,type):


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

def get_aspa(logger, hostname="savopkrill.com", port_number=3000, pwd="krill"):
    while True:
        try:
            headers = {"Authorization": f"Bearer {pwd}",
                       "Content-Type": "application/json"}
            url = f"https://{hostname}:{port_number}/api/v1/cas/testbed/aspas"
            response = requests.request(
                "GET", url, headers=headers, verify=False)
            response.raise_for_status()  # Raises an exception for any HTTP error status codes
            # Return the response as a dictionary
            temp = response.json()
            #TODO ipv6
            result = {}
            for row in temp:
                temp2 = []
                for s in row["providers"]:
                    s = s.replace("AS","")
                    s = s.replace("(v4)","")
                    s = int(s)
                    if not s in temp2:
                        temp2.append(s)
                result[row["customer"]] = temp2
            return result
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
        if data["customer"] == adj_customer_as:
            return adj_provider_as in data["providers"]
    return False

# def check_agent_agent_msg(msg):
#     """
#     message structure between agent and agent,
#     there are two types :'origin' and 'relay'
#     """
#     # self.as4_session = link_meta["as4_session"]
#     # self.protocol_name = link_meta["protocol_name"]
#     # check src dst
#     # raise an error if the given msg is not a valid agent to agent message
#     origin_key = "sav_origin"
#     path_key = "sav_path"
#     key_types = [("src",str),("dst",str),("msg_type",str),("sav_scope",list),
#                  ("sav_nlri",list),(origin_key,str),(path_key,list),("is_interior",bool)]
#     keys_types_check(msg,key_types)
#     if not msg["msg_type"] in ['origin','relay']:
#         raise ValueError(f"mst_type should be ether 'origin' or 'relay'")
    
#     for path in msg[path_key]:
#         if not tell_str_is_interior(path):
#             raise ValueError(f"{path_key} should contain path value")
    
#     if msg["is_interior"]:
#         if not tell_str_is_interior(msg[origin_key]):
#             raise ValueError(
#                 "interior msg should have interior path and origin")
#     return True
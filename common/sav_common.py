#!/usr/bin/python3
# -*-coding:utf-8 -*-
"""
@File    :   sav_common.py
@Time    :   2023/01/17 16:04:22
@Version :   0.1

@Desc    :   The sav_common.py contains shared functions and classes
"""

import os
import logging
import logging.handlers
import netaddr
import subprocess
import requests
import netifaces
from common.sav_data_structure import *


def subprocess_run(command):
    return subprocess.run(command, shell=True, capture_output=True, encoding='utf-8')


class RPDPPeer:
    def __init__(self, asn, port, ip, is_as4) -> None:
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
    for row in rows:
        heading = row.pop(0)
        # skip blackhole
        # if "blackhole" in heading:
        # continue
        prefix = heading.split(" ")[0]

        if "-" in prefix:
            logger.debug(prefix)
            prefix = prefix.split("-")[0]
            logger.debug(prefix)
        # TODO: demo filter
        if prefix == "0.0.0.0/0":
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
                if not temp == {}:
                    parsed_rows[prefix].append(temp)
                    temp = {}
        # add the last one
        if not temp == {}:
            parsed_rows[prefix].append(temp)
        # parsed_rows[prefix].sort()
        if len(parsed_rows[prefix]) == 1 and len(parsed_rows[prefix][0]) == 0:
            del parsed_rows[prefix]
    return table_name, parsed_rows


def check_msg(key, msg, meta=SAV_META):
    """check msg before sending to ensure the msg can be processed properly"""
    if key not in SAV_META:
        raise KeyError(f"key {key} not in SAV_META")
    keys_types_check(msg, meta[key])


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


def subproc_run(cmd, shell=True, capture_output=True, encoding='utf-8'):
    return subprocess.run(
        cmd,
        shell=shell,
        capture_output=capture_output,
        encoding=encoding)


def run_cmd(command):
    ret = subproc_run(command, shell=True,
                      capture_output=True, encoding='utf-8')
    if ret.returncode != 0:
        print(ret)
    return ret.stdout


def get_host_interface_list():
    """
    return a list of 'clean' interface names
    """
    command = "ip link|grep -v 'link' | grep -v -E 'docker0|lo' | awk -F: '{ print $2 }' | sed 's/ //g'"
    std_out = run_cmd(command=command)
    result = std_out.split("\n")[:-1]
    result = list(map(lambda x: x.split('@')[0], result))
    return [i for i in result if len(i) != 0]


def get_next_hop(target_ip):
    """
    find next hop for the given ip using ip route get
    """
    hex_hop = run_cmd(f"ip route get {target_ip}").split(" ")
    for i in range(len(hex_hop)):
        if hex_hop[i] == "via":
            return netaddr.IPAddress(hex_hop[i + 1])


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
    except BaseException:
        raise ValueError("invalid string: " + input_str)


def ln(list_of_interface):
    """
    return a a list of protocol_names
    """
    result = []
    for i in list_of_interface:
        result.append(i["protocol_name"])
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


def get_ifa_by_ip(ip):
    """
    return interface name by ip,
    using cmds
    """
    for ifa in get_host_interface_list():
        if ip.version == 6:
            temp = netifaces.ifaddresses(ifa).get(netifaces.AF_INET6, [])
        elif ip.version == 4:
            temp = netifaces.ifaddresses(ifa).get(netifaces.AF_INET, [])
        else:
            raise ValueError(ip)
        for link in temp:
            if link["addr"] == str(ip):
                return ifa
    raise ValueError(f"unable to get interface for {ip}")


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

    def put_link_up(self, link_name, link_type):
        # this msg may incur creating of new link, so we need to know the type
        msg = {
            "msg_type": "link_state_change",
            "source_app": self.name,
            "source_link": link_name,
            "link_type": link_type,
            "msg": True,
            "pkt_rec_dt": time.time()
        }
        self.agent.put_msg(msg)

    def set_link_type(self, link_name, link_type):
        # this msg may incur creating of new link, so we need to know the type
        msg = {
            "msg_type": "set_link_type",
            "source_app": self.name,
            "source_link": link_name,
            "msg": link_type,
            "pkt_rec_dt": time.time()
        }
        self.agent.put_msg(msg)

    def put_link_down(self, link_name):
        msg = {
            "msg_type": "link_state_change",
            "source_app": self.name,
            "source_link": link_name,
            "msg": False,
            "pkt_rec_dt": time.time()
        }
        self.agent.put_msg(msg)

    # def _bird_cmd(self, cmd):
    #     return birdc_cmd(self.logger, cmd)

    def _parse_roa_table(self, t_name='r4'):
        return get_roa(self.logger, t_name)


def birdc_cmd(logger, cmd, log_err=True):
    """
    execute bird command and return the output in std
    """
    t0 = time.time()
    cmd = f"/usr/local/sbin/birdc {cmd}"
    try:
        if "call_agent" in cmd:
            proc = subprocess.Popen(
                ["/usr/local/sbin/birdc", "call_agent"],
                stdout=subprocess.PIPE,
                stdin=subprocess.PIPE,
                stderr=subprocess.PIPE)
            proc.stdin.write("\n".encode("utf-8"))
            proc.stdin.flush()
            proc.wait()
            out = proc.stdout.read().decode()
        else:
            cmd = cmd.split(" ")
            proc = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stdin=subprocess.PIPE,
                stderr=subprocess.PIPE)
            out = proc.stdout.read()
            out = out.decode()
    except Exception as e:
        logger.debug(cmd)
        logger.debug(type(e))
        logger.error(e)
    t = time.time() - t0
    if t > TIMEIT_THRESHOLD:
        logger.debug(cmd)
        logger.warning(f"TIMEIT {time.time() - t0:.4f} seconds")
    temp = out.split("\n")[0]
    temp = temp.split()
    if len(temp) < 2:
        if log_err:
            logger.debug(cmd)
            logger.debug(proc.stderr.read())
            logger.error(temp)
            logger.error("length to short")
        return None
    if not (temp[0] == "BIRD" and temp[-1] == "ready."):
        logger.error(f"birdc execute error:{out}")
        return None
    out = "\n".join(out.split("\n")[1:])
    t = time.time() - t0
    # if t> TIMEIT_THRESHOLD:
    #     logger.warning(f"TIMEIT {time.time()-t0:.4f} seconds")
    return out


def birdc_show_protocols(logger):
    """
    execute show protocols
    """
    data = birdc_cmd(logger, cmd="show protocols")
    if data is None:
        return {}
    data = data.split("\n")
    while "" in data:
        data.remove("")
    return data


def birdc_get_protos_by(logger, key, value):
    data = birdc_show_protocols(logger)
    title = data.pop(0).split()
    result = []
    for row in data:
        temp = row.split()
        a = {}
        for i in range(min(len(title), len(temp))):
            a[title[i]] = temp[i]
        if key not in a:
            logger.error(f"key {key} missing in:{list(a.keys())}")
            return result
        if a[key] == value:
            result.append(a)
    return result


def parse_kernel_fib():
    """
    parsing the output of "route -n -F" command
    """
    v4table = run_cmd("route -n -F")
    v6table = run_cmd("route -6 -n -F")
    ret = {}
    for table in [v4table, v6table]:
        while "\t" in table:
            table = table.replace("\t", " ")
        while "  " in table:
            table = table.replace("  ", " ")
        table = table.split("\n")
        table.pop()  # removing tailing empty line
        _ = table.pop(0)
        table = list(map(lambda x: x.split(" "), table))
        headings = table.pop(0)
        table = list(map(lambda x: dict(zip(headings, x)), table))
        for row in table:
            if 'Genmask' in row:
                prefix = netaddr.IPNetwork(
                    row["Destination"] + "/" + row["Genmask"])
                ret[prefix] = row
            else:
                prefix = netaddr.IPNetwork(row["Destination"])
                ret[prefix] = row
    return ret


def birdc_get_import(logger, protocol_name, channel_name="ipv4"):
    """
    using birdc show all import to get import table
    return a list
    """
    cmd = f"show route all import table {protocol_name}.{channel_name}"
    data = birdc_cmd(logger, cmd)
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
        if table_name == "import":
            return table_data
    return []


def get_roa(logger, t_name='r4', ns_scope=None):
    """
    get ROA info from bird table
    """
    cmd = "show route table " + t_name
    row_str = []
    # detect if roa table have rows and stale
    last_len = -1
    for _ in range(30):
        data = birdc_cmd(logger, cmd)
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
            temp = d[0]
            temp = temp.split("/")
            if "-" in temp[1]:
                temp[1] = temp[1].split("-")[0]
            prefix = temp[0] + '/' + temp[1]
            if ns_scope:
                if as_number not in ns_scope:
                    continue
            if as_number not in result:
                result[as_number] = []
            result[as_number].append(netaddr.IPNetwork(prefix))
            # result[as_number].append(prefix)
    return result


def get_p_by_asn(asn, roa, aspa):
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
        for customer_asn, providers in aspa.items():
            if element_exist_check(ass, providers):
                if customer_asn not in ass:
                    ass.append(customer_asn)
                    for p in roa[customer_asn]:
                        if p not in result:
                            result[p] = customer_asn
                    added = True
    return result


def element_exist_check(a, b):
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
    # def
    # __init__(self,link_name,source_app,remote_addr,remote_as,local_addr,local_as,interface,type):


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


def get_aspa(logger, hostname="savopkrill.com", port_number=3000, pwd="krill"):
    while True:
        try:
            headers = {"Authorization": f"Bearer {pwd}",
                       "Content-Type": "application/json"}
            url = f"https://{hostname}:{port_number}/api/v1/cas/testbed/aspas"
            response = requests.request(
                "GET", url, headers=headers, verify=False, timeout=15)
            response.raise_for_status()  # Raises an exception for any HTTP error status codes
            # Return the response as a dictionary
            temp = response.json()
            # TODO ipv6
            result = {}
            for row in temp:
                temp2 = []
                for s in row["providers"]:
                    s = s.replace("AS", "")
                    s = s.replace("(v4)", "")
                    s = int(s)
                    if s not in temp2:
                        temp2.append(s)
                result[row["customer"]] = temp2
            return result
        except Exception as err:
            logger.error(err)
            time.sleep(0.1)


def aspa_check(meta, aspa_info):
    """
    return True if the meta is in the aspa_info
    """
    # TODO: ipv6
    adj_provider_as = f"AS{meta['meta']['local_as']}(v4)"
    adj_customer_as = meta["remote_as"]
    for data in aspa_info:
        if data["customer"] == adj_customer_as:
            return adj_provider_as in data["providers"]
    return False


TIMEIT_THRESHOLD = 0.5


def sav_timer(logger):
    def timer_func(func):
        # This function shows the execution time of
        # the function object passed
        def wrap_func(*args, **kwargs):
            t1 = time.time()
            result = func(*args, **kwargs)
            t2 = time.time()
            logger.debug(
                f'Function {func.__name__!r} executed in {(t2 - t1):.4f}s')
            return result
        return wrap_func
    return timer_func
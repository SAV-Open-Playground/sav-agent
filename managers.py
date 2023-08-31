# -*-coding:utf-8 -*-
'''
@File    :   managers.py
@Time    :   2023/01/17
@Author  :   Yuqian Shi
@Version :   0.1

@Desc    :   the managers.py is responsible for the execution of selected sav mechanism and other manager classes
'''
import subprocess
import json
from model import db
from model import SavInformationBase, SavTable
from sav_common import *

KEY_WORD = "SAVAGENT"
DATA_PATH = "/root/sav-agent/data"


def command_executor(command):
    return subprocess.run(command, shell=True, capture_output=True, encoding='utf-8')


def huawei_acl_generator(acl_sav_rule):
    status = command_executor(
        command=f'cat /dev/null > {DATA_PATH}/huawei_acl_rule.txt')
    status = command_executor(
        command=f'echo "system-view" >> {DATA_PATH}/huawei_acl_rule.txt')
    for iface, prefix_set in acl_sav_rule.items():
        status = command_executor(
            command=f'echo "acl name sav_{iface}" >> {DATA_PATH}/huawei_acl_rule.txt')
        for prefix in prefix_set:
            status = command_executor(
                command=f'echo "rule deny {prefix} 0.0.0.255" >> {DATA_PATH}/huawei_acl_rule.txt')
        status = command_executor(
            command=f'echo "quit" >> {DATA_PATH}/huawei_acl_rule.txt')
        status = command_executor(
            command=f'echo "interface Ethernet {iface}" >> {DATA_PATH}/huawei_acl_rule.txt')
        status = command_executor(
            command=f'echo acl sav_{iface} inbound >> {DATA_PATH}/huawei_acl_rule.txt')
        status = command_executor(
            command=f'echo "quit" >> {DATA_PATH}/huawei_acl_rule.txt')
    status = command_executor(
        command=f'echo "save" >> {DATA_PATH}/huawei_acl_rule.txt')


def h3c_acl_generator(acl_sav_rule):
    status = command_executor(
        command=f'cat /dev/null > {DATA_PATH}/h3c_acl_rule.txt')
    status = command_executor(
        command=f'echo "system-view" >> {DATA_PATH}/h3c_acl_rule.txt')
    for iface, prefix_set in acl_sav_rule.items():
        status = command_executor(
            command=f'echo "acl name sav_{iface}" >> {DATA_PATH}/h3c_acl_rule.txt')
        for prefix in prefix_set:
            status = command_executor(
                command=f'echo "rule deny {prefix} 0.0.0.255" >> {DATA_PATH}/h3c_acl_rule.txt')
        status = command_executor(
            command=f'echo "quit" >> {DATA_PATH}/h3c_acl_rule.txt')
        status = command_executor(
            command=f'echo "interface Ethernet {iface}" >> {DATA_PATH}/h3c_acl_rule.txt')
        status = command_executor(
            command=f'echo acl sav_{iface} inbound >> {DATA_PATH}/h3c_acl_rule.txt')
        status = command_executor(
            command=f'echo "quit" >> {DATA_PATH}/h3c_acl_rule.txt')
    status = command_executor(
        command=f'echo "save" >> {DATA_PATH}/h3c_acl_rule.txt')


def router_acl_refresh(active_app, logger):
    if active_app is None:
        return
    # TODO dynamic changing
    with open('/root/savop/SavAgent_config.json', 'r') as file:
        config = json.load(file)
        enabled_sav_app = config.get("enabled_sav_app")
    if enabled_sav_app is None:
        return
    session = db.session
    rules = session.query(SavTable).filter(SavTable.source == active_app).all()
    session.close()
    if len(rules) == 0:
        return f"there is no {active_app} sav rules, so don't need to refresh ACL"
    interface_set = set(get_host_interface_list())
    sav_rule = {}
    for rule in rules:
        prefix, interface = rule.prefix.split("/")[0], rule.interface
        if interface == "*":
            continue
        if prefix not in sav_rule.keys():
            sav_rule[prefix] = {interface}
        else:
            sav_rule[prefix].add(interface)
    for key, value in sav_rule.items():
        sav_rule[key] = interface_set - value
    acl_sav_rule = {}
    for prefix, iface_set in sav_rule.items():
        for iface in iface_set:
            if iface not in acl_sav_rule:
                acl_sav_rule[iface] = {prefix}
            else:
                acl_sav_rule[iface].add(prefix)
    # acl rule generator
    huawei_acl_generator(acl_sav_rule=acl_sav_rule)
    h3c_acl_generator(acl_sav_rule=acl_sav_rule)
    log_info = f"refresh sav_{active_app} acl successfully"
    logger.info(log_info)
    return log_info


def iptable_static_refresh(active_app, logger, rules):
    interface_set = set(get_host_interface_list())
    # using white list mode for EFP-uRPF
    if active_app in ["EFP-uRPF-Algorithm-A_app", "EFP-uRPF-Algorithm-B_app"]:
        for r in rules:
            add_rule_status = subprocess.call(
                ['iptables', '-A', KEY_WORD, '-i', r.interface, '-s', r.prefix, '-j', 'ACCEPT'])
        for interface in interface_set:
            add_rule_status = subprocess.call(
                ['iptables', '-A', KEY_WORD, '-i', interface, '-s', '192.168.0.0/16', '-j', 'DROP'])
    else:
        sav_rule = {}
        for rule in rules:
            prefix, interface = rule.prefix, rule.interface
            if interface == "*":
                continue
            if prefix not in sav_rule.keys():
                sav_rule[prefix] = {interface}
            else:
                sav_rule[prefix].add(interface)
        for key, value in sav_rule.items():
            sav_rule[key] = interface_set - value
        for prefix, iface_set in sav_rule.items():
            for iface in iface_set:
                add_rule_status = subprocess.call(
                    ['iptables', '-A', KEY_WORD, '-i', iface, '-s', prefix, '-j', 'DROP'])
    log_info = f"refresh {active_app} iptables successfully"
    logger.info(log_info)
    return log_info


def iptables_link_tc(active_app, logger, rules):
    interface_set = get_host_interface_list()
    # using white list mode for EFP-uRPF
    if active_app in ["EFP-uRPF-Algorithm-A_app", "EFP-uRPF-Algorithm-B_app"]:
        for r in rules:
            tc_handle = interface_set.index(r.interface) + 1
            add_rule_status = subprocess.call(
                ['iptables', '-A', KEY_WORD, '-i', r.interface, '-s', r.prefix, '-j', 'MARK', '--set-mark', tc_handle])
        for interface in interface_set:
            add_rule_status = subprocess.call(
                ['iptables', '-A', KEY_WORD, '-i', interface, '-s', '192.168.0.0/16', '-j', 'MARK'])
    else:
        sav_rule = {}
        for rule in rules:
            prefix, interface = rule.prefix, rule.interface
            if interface == "*":
                continue
            if prefix not in sav_rule.keys():
                sav_rule[prefix] = {interface}
            else:
                sav_rule[prefix].add(interface)
        for key, value in sav_rule.items():
            sav_rule[key] = interface_set - value
        for prefix, iface_set in sav_rule.items():
            for iface in iface_set:
                tc_handle = interface_set.index(iface) + 1
                add_rule_status = subprocess.call(['iptables', '-A', KEY_WORD, '-i', iface, '-s', prefix, '-j', 'MARK',
                                                   '--set-mark', tc_handle])
    log_info = f"refresh {active_app} iptables successfully"
    logger.info(log_info)
    return log_info


def iptables_refresh(active_app, logger, limit_rate=None):
    if active_app is None:
        logger.debug("active app is None")
        return
    # TODO dynamic changing
    with open('/root/savop/SavAgent_config.json', 'r') as f:
        config = json.load(f)
        enabled_sav_app = config.get("enabled_sav_app")
    if enabled_sav_app is None:
        logger.debug("enabled_sav_app app is None")
        return
    session = db.session
    rules = session.query(SavTable).filter(SavTable.source == active_app).all()
    session.close()
    if len(rules) == 0:
        return f"there is no {active_app} sav rules, so don't need to refresh iptables"
    for r in rules:
        # logger.debug(f" 'direction':{r.direction}, 'id':{r.id}, 'interface':{r.interface}, 'metadata':{r.metadata}, \
        # 'neighbor_as':{r.neighbor_as}, 'prefix':{r.prefix}, 'source':{r.source}, 'local_role:{r.local_role}")
        pass
    # flush existing rules
    flush_chain_status = subprocess.call(['iptables', '-F', KEY_WORD])
    if flush_chain_status != 0:
        logger.error(f"flush {active_app} iptables failed")
    if (limit_rate is None) or (limit_rate is not True):
        log_info = iptable_static_refresh(active_app, logger, rules)
    else:
        log_info = iptables_link_tc(active_app, logger, rules)
    return log_info


class IPTableManager():
    """
    manage the STB with SQLite and Flask-SQLAlchemy
    generate iptables rules and apply them
    """

    def __init__(self, logger, active_app):
        """
        the rule generated by all apps will be added to DB,
        but only the rule generated by the active app will be applied via iptables or traffic control(tc) tools
        """
        self.logger = logger
        self.active_app = active_app
        create_chain_status = subprocess.call(['iptables', '-N', KEY_WORD])
        if create_chain_status != 0:
            return
        self.input_status = subprocess.call(
            ['iptables', '-I', 'INPUT', '-j', KEY_WORD])
        self.forward_status = subprocess.call(
            ['iptables', '-I', 'FORWARD', '-j', KEY_WORD])
        # init tc tool's qdisc, class, filter
        interface_list = get_host_interface_list()
        for index in range(0, len(interface_list)):
            init_tc_command = f"tc qdisc add dev {interface_list[index]} root handle 1: htb default 20 && " \
                              f"tc class add dev {interface_list[index]} parent 1:0 classid 1:1 htb rate 3Mbit && " \
                              f"tc filter add dev {interface_list[index]} parent 1:0 prio 1 protocol ip handle {str(index + 1)} fw flowid 1:1"
            print(init_tc_command)
            init_tc_status = self._command_executor(command=init_tc_command)

    def _command_executor(self, command):
        command_result = subprocess.run(
            command, shell=True, capture_output=True, encoding='utf-8')
        return command_result.returncode

    def _iptables_command_execute(self, command):
        command_result = self._command_executor(command=command)
        return command_result.returncode

    def add(self, data_list):
        """
        add list of rules to the STB
        currently only add ipv4 and inter-domain rules
        """
        # self.logger.debug(data_list)
        session = db.session
        src_apps = set()
        for data in data_list:
            prefix, src_app, interface, local_role = data.get(
                "prefix"), data.get("source_app"), data.get("interface"), data.get("local_role")
            if (prefix is None) or (src_app is None) or (interface is None):
                self.logger.error(f"Missing required fields [{data.keys()}]")
                raise ValueError("Missing required field")
            neighbor_as = data.get("neighbor_as")
            interface_list = get_host_interface_list()
            interface_list.append("*")
            if interface not in interface_list:
                self.logger.error(
                    f"the interface {interface} doesn't exit in the list:{interface_list}")
                raise ValueError("the interface doesn't exit!")
            rules_in_table = session.query(SavTable).filter(
                SavTable.prefix == prefix,
                SavTable.interface == interface,
                SavTable.source == src_app)
            if rules_in_table.count() != 0:
                # self.logger.warning("rule exists")
                # self.logger.debug(rules_in_table)
                # self.logger.debug(data)
                log_msg = f"SAV RULE EXISTS: {data}"
                # self.logger.info(log_msg)
                return
            src_apps.add(src_app)
            sib_row = SavTable(
                prefix=prefix,
                neighbor_as=neighbor_as,
                interface=interface,
                local_role=local_role,
                source=src_app,
                direction=None)
            session.add(sib_row)
            session.commit()
            log_msg = f"SAV RULE ADDED: {data}"
            self.logger.info(log_msg)
        session.close()
        # self.logger.debug(self.active_app)
        # if not (self.active_app in src_apps):
        # return
        # refresh_info = iptables_refresh(self.active_app, self.logger)
        # log_msg = f"IP TABLES CHANGED: {refresh_info}"
        # self.logger.debug(log_msg)

    def delete(self, input_id):
        session = db.session
        sib_row = session.query(SavTable).filter(
            SavTable.id == input_id).first()
        prefix, interface = sib_row.prefix, sib_row.interface
        session.delete(sib_row)
        session.commit()
        if session.query(SavTable).filter(SavTable.prefix == prefix).count() == 0:
            command = f"iptables -L -v -n --line-numbers | grep {interface} | grep {prefix}"
            command += " |awk '{ print $1 }' | xargs - I v1  iptables - D "
            command += f"{KEY_WORD} v1"
            self._iptables_command_execute(command=command)
        else:
            command = f"iptables -A {KEY_WORD} -i {interface} -s {prefix} -j DROP"
            self._iptables_command_execute(command=command)
        session.close()
        return {"code": "0000", "message": "success"}

    def read(self):
        session = db.session
        sib_tables = session.query(SavTable).all()
        data = []
        for row in sib_tables:
            data.append({"id": row.id,
                         "prefix": row.prefix,
                         "neighbor_as": row.neighbor_as,
                         "interface": row.interface,
                         "source": row.source,
                         "direction": row.direction,
                         "createtime": row.createtime,
                         "local_role": row.local_role})
        session.close()
        return data


class SIBManager():
    """
    manage the STB with SQLite and Flask-SQLAlchemy
    generate iptables rules and apply them
    this table stores the key and value of a dictionary object, both key and value must be string
    """

    def __init__(self, logger):

        self.logger = logger

    def upsert(self, key, value):
        """
        add or update a key-value pair in db, both key and value must in string format.
        """
        if not (isinstance(key, str) and isinstance(value, str)):
            raise TypeError("key and value must be string")
        if len(key) > 255 or len(key) < 1:
            raise ValueError(
                "key length must be less than 255 and value length must be greater than 0")
        session = db.session
        row = session.query(SavInformationBase).filter(
            SavInformationBase.key == key).first()
        if row:
            session.delete(row)
        new_row = SavInformationBase(key=key, value=value)
        session.add(new_row)
        session.commit()
        session.close()
        v = json.loads(value)
        msg = f"SIB UPDATED: {key}:"
        if isinstance(v, list):
            for i in v:
                msg += f"\n{i}"
        elif isinstance(v, dict):
            msg += f"\n{json.dumps(v, indent=4)}"
        else:
            msg += f"{v}"
            # self.logger.debug(type(v))
        # self.logger.debug(f"SIB UPDATED: {msg}")

    def delete(self, key):
        session = db.session
        row = session.query(SavInformationBase).filter(
            SavInformationBase.key == key).first()
        session.delete(row)
        session.commit()
        session.close()
        return {"code": "0000", "message": "success"}

    def read_all(self):
        session = db.session
        sib_tables = session.query(SavInformationBase).all()
        data = []
        for row in sib_tables:
            data.append({row.key: row.value})
        session.close()
        return data


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


class LinkManager(InfoManager):
    """
    LinkManager manage the link status and preprocessing the msg from the link
    link_name is key MUST not be same
    the link_name should be link_type_src_ip_dst_ip
    """
    # TODO: we have three types of link: native bgp, modified bgp and grpc

    def __init__(self, data, logger=None):
        super(LinkManager, self).__init__(data, logger)

    def add(self, meta_dict):
        self._is_good_meta(meta_dict)
        # self.logger.debug(f"adding {meta_dict}")
        link_type = meta_dict["link_type"]
        link_name = self._get_link_name(meta_dict)
        # self.logger.debug(f"adding {link_name}")
        if link_name in self.data:
            self.logger.warning(f"key {link_name} already exists")
            return
        if not link_type in ["native_bgp", "modified_bgp",]:
            self.logger.error(f'unknown link_type: {link_type}')
            return
        self.data[link_name] = meta_dict
        self.logger.debug(f"link added: {link_name} ")

    def _get_link_name(self, meta_dict):
        return meta_dict["protocol_name"]

    # def is_mapped(self,link_map,link_name):
    #     """return the correct link_type and info for this link"""
    #     if not link_name in self.data:
    #         raise KeyError(f"link_name {link_name} not found")
    #     ifa = self.data[link_name]["interface_name"]
    #     return link_map.get(ifa,None)
    def update_link(self, meta_dict):
        self._is_good_meta(meta_dict)
        link_name = self._get_link_name(meta_dict)
        old_meta = self.data[link_name]
        if old_meta["status"] == meta_dict["status"]:
            return 
        self.data[link_name] = meta_dict
        self.logger.debug(f"link updated: {self.data[link_name]} ")

    def get_by_name_type(self, link_name,link_type=None):
        if link_name not in self.data:
            self.logger.debug(f"all link names:{self.data.keys()}")
            raise KeyError(f"link {link_name} not found")
        return self.data[link_name]

    def get_by(self, remote_as, is_interior):
        """return a list of link objects that matches both remote_as,is_interior
        """
        result = []
        if not is_asn(remote_as):
            raise ValueError(f"{remote_as} is not a valid asn")
        for _,link in self.data.items():
            if (link["remote_as"] == remote_as) and (
                    link["is_interior"] == is_interior):
                result.append(link)
        return result
    def get_by_kv(self, k,v):
        """return a list of link_names that matches the key and value
        """
        result = []
        for link_name,meta in self.data.items():
            if not k in meta:
                raise ValueError(f"{k} is not a valid key")
            if meta[k] == v:
                result.append(link_name)
        return result
    def rpdp_links(self,link_map):
        """return a list of link_name and link_data tuple that are rpdp links
        """
        results = []
        for link_name,link in self.data.items():
            # self.logger.debug(link["protocol_name"] )
            # self.logger.debug(link_map.keys() )
            if link["protocol_name"] in link_map:
                results.append((link_name,link))
            elif link["link_type"] == "modified_bgp":
                results.append((link_name,link))
            else:
                self.logger.debug(f"ignoring no sav link: {link_name}")
        return results
    def get_all_up(self, include_native_bgp=False):
        """
        return a list of all up link_names ,use get(link_name) to get link object
        """
        temp = []
        for link_name,link in self.data.items():
            # self.logger.debug(link["protocol_name"])
            if link["status"]:
                if link["link_type"] == "native_bgp":
                    # self.logger.debug(link["protocol_name"])
                    if include_native_bgp:
                        temp.append(link_name)
                else:
                    temp.append(link_name)
        return temp

    def get_all_up_type(self, is_interior, include_native_bgp=False):
        """
        return a list of all up link_names with the correct type (is_interior or not),
        use get(link_name) to get link object
        """
        result = []
        for link_name in self.get_all_up(include_native_bgp):
            if self.data[link_name]["is_interior"] == is_interior:
                result.append(link_name)
        return result

    def get_bgp_by_interface(self, interface_name):
        """
        return a list of bgp(modified or native) link_dict that has the same interface_name
        """
        # self.logger.debug(f"interface_name:{interface_name}")
        result = []
        # self.logger.debug(self.data)
        for _,link in self.data.items():
            # self.logger.debug(link)
            if link["interface_name"] == interface_name:
                result.append(link)
        # self.logger.debug(f"result:{result}")
        return result

    def exist(self, link_name):
        return link_name in self.data

    def _is_good_meta(self, meta):
        key_types = [("remote_as", int), ("local_as", int),
                     ("remote_ip", str), ("local_ip", str),
                     ("local_role", str), ("remote_role", str),
                     ("interface_name", str), ("link_type", str),
                     ("protocol_name", str), ("as4_session",bool),
                     ("is_interior", bool), ("status", bool),
                     ("initial_broadcast", bool)]
        keys_types_check(meta, key_types)
        if not meta["link_type"] in ["native_bgp", "modified_bgp"]:
            raise ValueError(f'unknown link_type: {meta["link_type"]}')
        return True


def get_new_link_meta(app_name, link_type, initial_status=False):
    """
    generate a new link meta dict for adding,dummy data provided, remember to change it
    """
    meta = {"remote_as": 0,
            "remote_ip": "",
            "local_role": "",
            "remote_role":"",
            "local_ip": "",
            "local_as":0,
            "interface_name": "",
            "protocol_name": "",
            "as4_session": True,
            "is_interior": True,
            "link_type": link_type,
            "status": initial_status,
            "initial_broadcast": False,
            "app": app_name
            }
    return meta
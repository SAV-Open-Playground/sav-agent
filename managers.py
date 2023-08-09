# -*-coding:utf-8 -*-
'''
@File    :   db_manager.py
@Time    :   2023/01/17
@Author  :   Yuqian Shi
@Version :   0.1

@Desc    :   the db_manager.py is responsible for the execution of selected sav mechanism 
'''
import subprocess
import json
from model import db
from model import SavInformationBase, SavTable
from sav_common import *

KEY_WORD = "SAVAGENT"


def iptables_command_execute(sender, prefix, neighbor_as, interface, **extra):
    add_rule_status = subprocess.call(
        ['iptables', '-A', KEY_WORD, '-i', interface, '-s', prefix, '-j', 'DROP'])


def iptables_refresh(active_app, logger):
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
        return f"there is no {active_app} sav rules, so don't need to refresh iptables"
    # flush existing rules
    flush_chain_status = subprocess.call(['iptables', '-F', KEY_WORD])
    interface_set = set(get_host_interface_list())
    # using whilt list mode for EFP-uRPF
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


class IPTableManager():
    """
    manage the STB with SQLite and Flask-SQLAlchemy
    generate iptables rules and apply them
    """

    def __init__(self, logger, active_app):
        """
        the rule generated by all apps will be added to DB,
        but only the rule generated by the active app will be applied via iptables
        """
        create_chain_status = subprocess.call(['iptables', '-N', KEY_WORD])
        if create_chain_status != 0:
            return
        self.input_status = subprocess.call(
            ['iptables', '-I', 'INPUT', '-j', KEY_WORD])
        self.forward_status = subprocess.call(
            ['iptables', '-I', 'FORWARD', '-j', KEY_WORD])
        self.logger = logger
        self.active_app = active_app

    def _command_executer(self, command):
        return

    def _iptables_command_execute(self, command):
        command_result = self._command_executer(command=command)
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
            self.logger.warn(log_msg)
        session.close()
        # self.logger.debug(src_apps)
        # self.logger.debug(self.active_app)
        # if not (self.active_app in src_apps):
        # return
        refresh_info = iptables_refresh(self.active_app, self.logger)
        log_msg = f"IP TABLES CHANGED: {refresh_info}"
        self.logger.debug(log_msg)

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
                         "createtime": row.createtime})
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
    """
    # TODO: we have three types of link: native bgp, modified bgp and grpc

    def __init__(self, data, logger=None):
        super(LinkManager, self).__init__(data, logger)

    def add(self, link_name, link_dict, link_type):
        if "rpki" in link_name:
            return
        # self.logger.debug(f"adding {link_name},{link_dict}")
        if link_name in self.data:
            self.logger.warning(f"key {link_name} already exists")
            return
        if not link_type in ["native_bgp", "modified_bgp", "grpc"]:
            self.logger.error(f'unknown link_type: {link_type}')
            return
        link_dict_keys = [("meta", dict)]
        keys_types_check(link_dict, link_dict_keys)
        meta_keys = [("remote_as", int), ("local_as", int)]
        keys_types_check(link_dict["meta"], meta_keys)
        link_dict["link_type"] = link_type
        self.data[link_name] = link_dict
        self.logger.debug(f"link added: {link_name} ")

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

    def get(self, link_name):
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
        for key in self.data:
            link = self.data[key]
            if (link["meta"]["remote_as"] == remote_as) and (
                    link["meta"]["is_interior"] == is_interior):
                result.append(link)
        return result

    def get_all_up(self, include_native_bgp=False):
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

    def get_all_up_type(self, is_interior, include_native_bgp=False):
        """
        return a list of all up link_names with the correct type (is_interior or not),
        use get(link_name) to get link object
        """
        result = []
        for link_name in self.get_all_up(include_native_bgp):
            if self.data[link_name]["meta"]["is_interior"] == is_interior:
                result.append(link_name)
        return result

    def get_all_grpc(self):
        """
        return a list of all grpc link_names
        """
        result = []
        for link_name in self.data:
            link = self.data[link_name]
            if link["link_type"] == "grpc":
                result.append(link_name)
        return result

    def exist(self, link_name):
        return link_name in self.data


def get_new_link_dict(app_name):
    """
    generate a new link dict for adding
    """

    link_dict = {"status": False, "initial_broadcast": False,
                 "app": app_name, "meta": get_new_link_meta()}
    return link_dict


def get_new_link_meta():
    """
    generate a new link meta dict for adding
    """
    meta = {"remote_as": 0, "local_as": 0}
    return meta

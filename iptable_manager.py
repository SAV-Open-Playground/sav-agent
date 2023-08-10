# -*-coding:utf-8 -*-
'''
@File    :   iptable_manager.py
@Time    :   2023/01/17
@Author  :   Yuqian Shi
@Version :   0.1

@Desc    :   the iptable_manager.py is responsible for the execution of selected sav mechanism 
'''
import subprocess
import json
from model import db
from model import SavInformationBase, SavTable
from sav_common import get_host_interface_list

KEY_WORD = "SAVAGENT"
DATA_PATH = "/root/sav-agent/data"


def iptables_command_execute(sender, prefix, neighbor_as, interface, **extra):
    add_rule_status = subprocess.call(
        ['iptables', '-A', KEY_WORD, '-i', interface, '-s', prefix, '-j', 'DROP'])


def command_executor(command):
    return subprocess.run(command, shell=True, capture_output=True, encoding='utf-8')


def huawei_acl_generator(acl_sav_rule):
    status = command_executor(command=f'cat /dev/null > {DATA_PATH}/huawei_acl_rule.txt')
    status = command_executor(command=f'echo "system-view" >> {DATA_PATH}/huawei_acl_rule.txt')
    for iface, prefix_set in acl_sav_rule.items():
        status = command_executor(command=f'echo "acl name sav_{iface}" >> {DATA_PATH}/huawei_acl_rule.txt')
        for prefix in prefix_set:
            status = command_executor(command=f'echo "rule deny {prefix} 0.0.0.255" >> {DATA_PATH}/huawei_acl_rule.txt')
        status = command_executor(command=f'echo "quit" >> {DATA_PATH}/huawei_acl_rule.txt')
        status = command_executor(command=f'echo "interface Ethernet {iface}" >> {DATA_PATH}/huawei_acl_rule.txt')
        status = command_executor(command=f'echo acl sav_{iface} inbound >> {DATA_PATH}/huawei_acl_rule.txt')
        status = command_executor(command=f'echo "quit" >> {DATA_PATH}/huawei_acl_rule.txt')
    status = command_executor(command=f'echo "save" >> {DATA_PATH}/huawei_acl_rule.txt')


def h3c_acl_generator(acl_sav_rule):
    status = command_executor(command=f'cat /dev/null > {DATA_PATH}/h3c_acl_rule.txt')
    status = command_executor(command=f'echo "system-view" >> {DATA_PATH}/h3c_acl_rule.txt')
    for iface, prefix_set in acl_sav_rule.items():
        status = command_executor(command=f'echo "acl name sav_{iface}" >> {DATA_PATH}/h3c_acl_rule.txt')
        for prefix in prefix_set:
            status = command_executor(command=f'echo "rule deny {prefix} 0.0.0.255" >> {DATA_PATH}/h3c_acl_rule.txt')
        status = command_executor(command=f'echo "quit" >> {DATA_PATH}/h3c_acl_rule.txt')
        status = command_executor(command=f'echo "interface Ethernet {iface}" >> {DATA_PATH}/h3c_acl_rule.txt')
        status = command_executor(command=f'echo acl sav_{iface} inbound >> {DATA_PATH}/h3c_acl_rule.txt')
        status = command_executor(command=f'echo "quit" >> {DATA_PATH}/h3c_acl_rule.txt')
    status = command_executor(command=f'echo "save" >> {DATA_PATH}/h3c_acl_rule.txt')


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
    # using white list mode for EFP-uRPF
    if active_app in ["EFP-uRPF-Algorithm-A_app", "EFP-uRPF-Algorithm-B_app"]:
        for r in rules:
            add_rule_status = subprocess.call(['iptables', '-A', KEY_WORD, '-i', r.interface, '-s', r.prefix, '-j', 'ACCEPT'])
        for interface in interface_set:
            add_rule_status = subprocess.call(['iptables', '-A', KEY_WORD, '-i', interface, '-s', '192.168.0.0/16', '-j', 'DROP'])
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
                add_rule_status = subprocess.call(['iptables', '-A', KEY_WORD, '-i', iface, '-s', prefix, '-j', 'DROP'])
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
        return subprocess.run(command, shell=True, capture_output=True, encoding='utf-8')

    def _get_host_interface_list(self):
        return get_host_interface_list()

    def _iptables_command_execute(self, command):
        command_result = self._command_executer(command=command)
        return command_result.returncode
    def add(self,data_list):
        """
        add list of rules to the STB
        currently only add ipv4 and inter-domain rules
        """
        # self.logger.debug(data_list)
        session = db.session
        src_apps = set()
        for data in data_list:
            prefix, src_app, interface,local_role = data.get(
            "prefix"), data.get("source_app"), data.get("interface"),data.get("local_role")
            if (prefix is None) or (src_app is None) or (interface is None):
                self.logger.error(f"Missing required fields [{data.keys()}]")
                raise ValueError("Missing required field")
            neighbor_as = data.get("neighbor_as")
            interface_list = self._get_host_interface_list()
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
                self.logger.warning("rule exists")
                log_msg = f"SAV RULE EXISTS: {data}"
                self.logger.info(log_msg)
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
        # refresh_info = iptables_refresh(self.active_app, self.logger)
        # log_msg = f"IP TABLES CHANGED: {refresh_info}"
        router_acl_refresh(self.active_app, self.logger)
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
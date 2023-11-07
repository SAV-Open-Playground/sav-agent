# -*-coding:utf-8 -*-
'''
@File    :   managers.py
@Time    :   2023/01/17
@Version :   0.1

@Desc    :   the managers.py is responsible for the execution of selected sav mechanism and other manager classes
'''
import subprocess
import json
import queue

from model import db
from model import SavInformationBase, SavTable
from sav_common import *

KEY_WORD = "SAVAGENT"
DATA_PATH = "/root/sav-agent/data"


def huawei_acl_generator(acl_sav_rule):
    status = subprocess_run(
        command=f'cat /dev/null > {DATA_PATH}/huawei_acl_rule.txt')
    status = subprocess_run(
        command=f'echo "system-view" >> {DATA_PATH}/huawei_acl_rule.txt')
    for iface, prefix_set in acl_sav_rule.items():
        status = subprocess_run(
            command=f'echo "acl name sav_{iface}" >> {DATA_PATH}/huawei_acl_rule.txt')
        for prefix in prefix_set:
            status = subprocess_run(
                command=f'echo "rule deny {prefix} 0.0.0.255" >> {DATA_PATH}/huawei_acl_rule.txt')
        status = subprocess_run(
            command=f'echo "quit" >> {DATA_PATH}/huawei_acl_rule.txt')
        status = subprocess_run(
            command=f'echo "interface Ethernet {iface}" >> {DATA_PATH}/huawei_acl_rule.txt')
        status = subprocess_run(
            command=f'echo acl sav_{iface} inbound >> {DATA_PATH}/huawei_acl_rule.txt')
        status = subprocess_run(
            command=f'echo "quit" >> {DATA_PATH}/huawei_acl_rule.txt')
    status = subprocess_run(
        command=f'echo "save" >> {DATA_PATH}/huawei_acl_rule.txt')


def h3c_acl_generator(acl_sav_rule):
    status = subprocess_run(
        command=f'cat /dev/null > {DATA_PATH}/h3c_acl_rule.txt')
    status = subprocess_run(
        command=f'echo "system-view" >> {DATA_PATH}/h3c_acl_rule.txt')
    for iface, prefix_set in acl_sav_rule.items():
        status = subprocess_run(
            command=f'echo "acl name sav_{iface}" >> {DATA_PATH}/h3c_acl_rule.txt')
        for prefix in prefix_set:
            status = subprocess_run(
                command=f'echo "rule deny {prefix} 0.0.0.255" >> {DATA_PATH}/h3c_acl_rule.txt')
        status = subprocess_run(
            command=f'echo "quit" >> {DATA_PATH}/h3c_acl_rule.txt')
        status = subprocess_run(
            command=f'echo "interface Ethernet {iface}" >> {DATA_PATH}/h3c_acl_rule.txt')
        status = subprocess_run(
            command=f'echo acl sav_{iface} inbound >> {DATA_PATH}/h3c_acl_rule.txt')
        status = subprocess_run(
            command=f'echo "quit" >> {DATA_PATH}/h3c_acl_rule.txt')
    status = subprocess_run(
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
    try:
        if active_app is None:
            logger.debug("active app is None")
            return
        # TODO dynamic changing
        # tell if current node is sav enabled
        with open('/root/savop/SavAgent_config.json', 'r') as f:
            config = json.load(f)
            enabled_sav_app = config.get("enabled_sav_app")
        if enabled_sav_app is None:
            logger.debug("enabled_sav_app app is None")
            return
        session = db.session
        rules = session.query(SavTable).filter(
            SavTable.source == active_app).all()
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
    except Exception as e:
        logger.error(e)
        logger.exception(e)
        return f"refresh {active_app} iptables failed"


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
        self.sav_rules = {}
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

    def add_old(self, data_list):
        """
        add list of rules to the STB
        currently only add ipv4 and inter-domain rules
        """
        if len(data_list) == 0:
            return
        self.logger.debug(f"BEGIN inserting {len(data_list)}")
        session = db.session
        src_apps = set()
        for data in data_list:
            prefix, src_app, interface, local_role = data.get(
                "prefix"), data.get("source_app"), data.get("interface"), data.get("local_role")
            if (prefix is None) or (src_app is None) or (interface is None):
                self.logger.error(f"Missing required fields [{data.keys()}]")
                raise ValueError("Missing required field")
            # update local dict
            if not src_app in self.sav_rules:
                self.sav_rules[src_app] = {}

            neighbor_as = data.get("neighbor_as")
            interface_list = get_host_interface_list()
            interface_list.append("*")
            if interface not in interface_list:
                self.logger.error(
                    f"the interface {interface} doesn't exit in the list:{interface_list}")
                self.logger.error(
                    f"sav rule {data} is not added")
                continue
            rules_in_table = session.query(SavTable).filter(
                SavTable.prefix == prefix,
                SavTable.interface == interface,
                SavTable.source == src_app)
            if rules_in_table.count() != 0:
                log_msg = f"SAV RULE EXISTS: {data}"
                # self.logger.debug(log_msg)
                continue
            src_apps.add(src_app)
            sib_row = SavTable(
                prefix=prefix,
                neighbor_as=neighbor_as,
                interface=interface,
                local_role=local_role,
                source=src_app,
                direction=None)
            # self.logger.debug(dir(session))
            try:
                session.add(sib_row)
            except Exception as e:
                self.logger.error(e)
                self.logger.exception(e)
                continue
            # log_msg = f"SAV RULE ADDED: {data}"
            # self.logger.info(log_msg)
        session.commit()
        session.close()
        self.logger.debug(f"END inserting {len(data_list)}")

    def add(self, data_list):
        """
        add list of rules to the STB
        currently only add ipv4 and inter-domain rules
        """
        if len(data_list) == 0:
            return
        self.logger.debug(f"BEGIN inserting {len(data_list)}")
        session = db.session
        interface_list = get_host_interface_list()
        interface_list.append("*")
        batch_data = []
        for data in data_list:
            prefix, src_app, interface, local_role = data.get("prefix"), data.get(
                "source_app"), data.get("interface"), data.get("local_role")
            if (prefix is None) or (src_app is None) or (interface is None):
                self.logger.error(f"Missing required fields [{data.keys()}]")
                raise ValueError("Missing required field")
            # update local dict
            # if not src_app in self.sav_rules:
            #     self.sav_rules[src_app] = {}
            neighbor_as = data.get("neighbor_as")
            if interface not in interface_list:
                self.logger.error(
                    f"the interface {interface} doesn't exit in the list:{interface_list}")
                self.logger.error(
                    f"sav rule {data} is not added")
                continue
            if session.query(SavTable).filter_by(prefix=prefix, interface=interface, source=src_app).first() is not None:
                # log_msg = f"SAV RULE EXISTS: {data}"
                # self.logger.debug(log_msg)
                continue
            sib_row = SavTable(
                prefix=prefix,
                neighbor_as=neighbor_as,
                interface=interface,
                local_role=local_role,
                source=src_app,
                direction=None)
            batch_data.append(sib_row)
            if len(batch_data) == 300:
                try:
                    session.bulk_save_objects(batch_data)
                    session.commit()
                    batch_data = []
                except Exception as e:
                    self.logger.error(e)
                    self.logger.exception(e)
                    continue
        if len(batch_data) > 0:
            session.bulk_save_objects(batch_data)
            session.commit()
        session.close()
        self.logger.debug(f"END inserting {len(data_list)}")

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


class BirdCMDManager():
    """manage the execution of bird command, avoid concurrency issue"""

    def __init__(self, logger) -> None:
        self.logger = logger
        self.cmd_list = []
        self.is_running = False
        self.bird_fib = {"check_time": None, "update_time": None, "local_route": {},
                         "remote_route": {}, "default_route": {}}

    def is_bird_ready(self):
        """
        return True if bird is ready
        """
        try:
            result = self.bird_cmd("show status", log_err=False)
            if result:
                return True
            else:
                return False
        except:
            return False

    def bird_cmd(self, cmd, log_err=True):
        while self.is_running:
            time.sleep(0.01)
        self.is_running = True
        ret = birdc_cmd(self.logger, cmd, log_err)
        self.is_running = False
        return ret

    def update_protocols2(self):
        """
        using birdc show protocols all to get bird protocols info, very slow
        """
        check_time = time.time()
        while True:
            raw_result = self.bird_cmd("show protocols all", False)
            if raw_result:
                new_ = self._parse_protocols(raw_result)
                all_good = True
                for p, d in new_.items():
                    if p.startswith("savbgp"):
                        if d["meta"] is None:
                            self.logger.warning(f"{p} meta is None")
                        all_good = False
                if all_good:
                    break
            time.sleep(0.1)
        return new_,check_time

    def get_link_by_name(self, name):
        """all links must startswith savbgp"""
        if not name.startswith("savbgp"):
            raise ValueError(f"invalid name: {name}")
        if not name in self.protos["links"]:
            raise ValueError(f"link {name} not found")
        return self.protos["links"].get(name)



    def parse_link_meta(self, proto_data):
        """
        update link meta data
        """
        try:
            # self.logger.debug(json.dumps(proto_data, indent=2))
            t = proto_data["links"]["BGP state:          Established"]
            meta = {
                "interface_name": t["Neighbor address"].split("%")[1],
                "remote_as": int(t["Neighbor AS"]),
                "local_role": t["Local capabilities"]["Role"],
                "local_as": int(t["Local AS"]),
                "local_ip": t["Source address"],
                "remote_ip": t["Neighbor address"].split("%")[0],
                "status": proto_data["State"] == "up",
                "initial_broadcast": False,
                "as4_session": "4-octet AS numbers" in t["Local capabilities"],
                "protocol_name": proto_data["Name"]
            }
            if "rpdp" in str(t):
                meta["link_type"] = "dsav"
            else:
                meta["link_type"] = "native_bgp"
            meta["is_interior"] = (meta["remote_as"] != meta["local_as"])
            # self.logger.debug(json.dumps(meta, indent=2))
            return meta
        except KeyError as e:
            # self.logger.error(e)
            # self.logger.exception(e)
            return None


    def get_by_remote_as_is_inter(self, remote_as, is_interior):
        result = []
        for link_name, data in self.protos["links"].items():
            if "meta" not in data:
                continue
            if not data["meta"]:
                continue
            meta = data["meta"]
            if (meta["remote_as"] == remote_as) and (
                    meta["is_interior"] == is_interior):
                result.append(meta)
        return result



    def get_up_inter_links(self):
        result = {}
        for proto, data in self.protos["links"].items():
            if data["meta"]["is_interior"]:
                result[proto] = data
        return result

    def get_proto(self, proto_name):
        if not proto_name in self.protos:
            raise ValueError(
                f"proto_name {proto_name} not found in {list(self.protos.keys())}")
        return self.protos.get(proto_name, None)

    def _parse_next_level(self, raw_input, indent=2):
        # self.logger.debug(json.dumps(raw_input, indent=2))
        result = {}
        last_key = None
        special_cases = ["Description", "Neighbor AS", "Local AS",
                         "Neighbor address", "Role", "Source address"]
        for line in raw_input:
            # self.logger.debug(line)
            if line.startswith(" "*indent):
                if last_key is None:
                    self.logger.error("last_key is None")
                    self.logger.error(line)
                    continue
                result[last_key].append(line[indent:])
            else:
                line = line.strip()
                found = False
                for k in special_cases:
                    if line.startswith(k):
                        key, value = line.split(":")
                        if key in result:
                            self.logger.error(f"key {key} already exists")
                            self.logger.error(line)
                            continue

                        result[key] = value.strip()
                        found = True
                        break
                if not found:
                    result[line] = []
                last_key = line
        for k, v in result.items():
            if type(v) == list:
                result[k] = self._parse_next_level(v, indent=indent)
        return result

    def _parse_links(self, raw_input):
        """
        parse link data inside proto_data
        """
        for key1, data in raw_input.items():
            if not key1.startswith("savbgp"):
                continue
            temp = data["sub_1"]
            del raw_input[key1]["sub_1"]
            result = self._parse_next_level(temp)
            raw_input[key1]["links"] = result
            # self.logger.debug(json.dumps({key1: raw_input[key1]}, indent=2))
        return raw_input


    def _parse_protocols(self, raw_input):
        lines = raw_input.split("\n")
        headings = lines.pop(0).split()
        result = {}
        this_proto = None
        for l in lines:
            if len(l) < 1:
                continue
            if not l.startswith(" "):
                current_headings = l.split()
                this_proto = current_headings[0]
                result[this_proto] = dict(
                    zip(headings, current_headings))
                # self.logger.debug(result[this_proto])
                result[this_proto]["sub_1"] = []
            elif l.startswith("  "):
                result[this_proto]["sub_1"].append(l[2:])
            else:
                self.logger.error(f"unknown heading: {l}")
        result = self._parse_links(result)
        for p, d in result.items():
            if p.startswith("savbgp"):
                d["meta"] = self.parse_link_meta(d)
                result[p] = d
        return result

    def update_fib(self, ip_version, log_err=True, insert_db=False, sib_man=None):
        """
        return adds, dels of bird fib
        """
        self.logger.debug("updating fib")
        self.bird_fib["check_time"] = time.time()
        default, local, remote = self._parse_bird_fib(log_err, ip_version)
        self.logger.debug(default)
        self.logger.debug(local)
        self.logger.debug(remote)
        something_updated = False
        local_adds, local_dels = self._diff_fib(
            self.bird_fib["local_route"], local)
        if len(local_adds) + len(local_dels) > 0:
            something_updated = True
            self.bird_fib["local_route"] = local
            # self.logger.debug(f"local_route updated")
        remote_adds, remote_dels = self._diff_fib(
            self.bird_fib["remote_route"], remote)
        if len(remote_adds) + len(remote_dels) > 0:
            something_updated = True
            self.bird_fib["remote_route"] = remote
            # self.logger.debug(f"remote_route updated")
        if default != self.bird_fib["default_route"]:
            self.bird_fib["default_route"] = default
            something_updated = True
            # self.logger.debug(f"default_route updated")
        if something_updated:
            self.bird_fib["update_time"] = self.bird_fib["check_time"]

    def _diff_fib(self, old_fib, new_fib):
        """
        return list of added and deleted rows in dict format
        """
        # self.logger.debug(f"old fib:{old_fib}, new_fib:{new_fib}")
        dels = {}
        adds = {}
        for prefix in new_fib:
            if not (new_fib.get(prefix, None) == old_fib.get(prefix, None)):
                adds[prefix] = new_fib[prefix]
        for prefix in old_fib:
            if not (new_fib.get(prefix, None) == old_fib.get(prefix, None)):
                dels[prefix] = old_fib[prefix]
        return adds, dels

    def get_local_fib(self):
        """"filter out local routes from fib"""
        return self.bird_fib["local_route"]

    def get_remote_fib(self):
        """"filter out remote routes from fib"""
        return self.bird_fib["remote_route"]

    def get_remote_local_fib(self):
        """"filter out remote and local routes from fib"""
        temp = {}
        for prefix, data in self.bird_fib["local_route"].items():
            temp[prefix] = data
        for prefix, data in self.bird_fib["remote_route"].items():
            temp[prefix] = data
        return temp

    def pre_process_table(self, table):
        """
        format the out put for latter use
        only tested in iBGP with IPv6
        """
        temp = {}
        for table_name, table_value in table.items():
            temp[table_name] = {}
            for prefix, data in table_value.items():
                temp[table_name][prefix] = {}
                for k, v in data.items():
                    new_k = k
                    if new_k.startswith("BGP."):
                        new_k = new_k[4:]
                    if new_k.endswith(":"):
                        new_k = new_k[:-1]
                    temp[table_name][prefix][new_k] = v
        del table
        return temp

    def _parse_bird_fib(self, log_err, ip_version):
        """
        using birdc show all to get bird fib,
        return prefix-as_path dict
        """
        t0 = time.time()
        data = self.bird_cmd("show route all", log_err)
        if data is None:
            return {}
        data = data.split("Table")
        while "" in data:
            data.remove("")
        result = {}
        for table in data:
            table_name, table_data = self._parse_bird_table(table, ip_version)
            result[table_name] = table_data
        temp_ret = {}
        if "master4" in result:
            temp_ret["master4"] = result["master4"]
        elif "master6" in result:
            temp_ret["master6"] = result["master6"]
        else:
            self.logger.warning(
                "no master4 table. Is BIRD ready?")
            return {}
        temp_ret = self.pre_process_table(temp_ret)
        default = {}
        local = {}
        remote = {}
        # self.logger.debug(f"{temp_ret}")
        for table_name, table_value in temp_ret.items():
            for prefix, data in table_value.items():
                # self.logger.debug(f"{prefix}:{data}")
                is_remote = ("as_path" in data)
                if prefix.prefixlen == 0:
                    default[prefix] = data
                elif not is_remote:
                    local[prefix] = data
                elif is_remote:
                    if not "interface" in data:
                        interface = None
                        for k in data:
                            if k.startswith("via "):
                                if interface is None:
                                    interface= k.split()[-1]
                    remote[prefix] = data
                    remote[prefix]["interface"] = interface
                else:
                    self.logger.error(prefix)
                    self.logger.error(json.dumps(data, indent=2))
                    self.logger.error("unknown prefix type")
            # del result[prefix]
        t = time.time() - t0
        if t > TIMEIT_THRESHOLD:
            self.logger.warning(f"TIMEIT {time.time()-t0:.4f} seconds")
        # self.logger.debug(remote)
        # self.logger.debug(local)
        # self.logger.debug(default)
        return default, local, remote

    def _parse_bird_table(self, table, ip_version):
        """
        return table_name (string) and parsed_rows (dict)
        """
        # self.logger.debug(table)
        t0 = time.time()
        temp = table.split("\n")
        while '' in temp:
            temp.remove('')

        table_name = temp[0][1:-1]
        parsed_rows = {}
        temp = temp[1:]
        rows = []
        this_row = []
        for line in temp:
            if not (line[0] == '\t' or line[0] == ' '):
                rows.append(this_row)
                this_row = [line]
            else:
                this_row.append(line)
        rows.append(this_row)
        while [] in rows:
            rows.remove([])
        # self.logger.debug(f"rows:{rows}")
        for row in rows:
            prefix = row.pop(0)
            # if "blackhole" in prefix:
            #     continue
            prefix = prefix.split(" ")[0]
            if len(prefix) < 9:
                self.logger.error(f"incorrect prefix len: {row}")
            # self.logger.debug(prefix)
            # TODO check correctness
            if "-" in prefix:
                prefix = prefix.split("-")[0]
            prefix = netaddr.IPNetwork(prefix)
            if prefix.version != ip_version:
                continue
            # if prefix.is_private():
            #     # self.logger.debug(f"private prefix {prefix} ignored")
            #     continue
            #
            temp = {}
            for line in row:
                if line.startswith("\t") and (":" in line):
                    line = line.strip()
                    line = line.split(": ")
                    k = line[0]
                    v = ":".join(line[1:])
                    # self.logger.debug(f"[{k}]:[{v}]")
                    temp[k] = v
                    if k == "BGP.as_path":
                        # self.logger.debug(f"v:{v}")
                        if not "as_path" in temp:
                            temp["as_path"] = []
                        temp["as_path"].append(list(map(int, v.split(" "))))
                        # self.logger.debug(f"as_path:{temp['as_path']}")
                        del temp["BGP.as_path"]
                elif line.startswith("\tdev"):
                    temp["interface"] = line.split(" ")[1]
                elif line.startswith("\tvia"):
                    temp["via"] = " ".join(line.split(" ")[1:])
                elif line.startswith("                     unicast"):
                    line = line.strip()
                    temp["source"] = line
                else:
                    self.logger.warning([line])
            if prefix in parsed_rows:
                self.logger.warning(f"prefix {str(prefix)} already exists")
            else:
                parsed_rows[prefix] = temp
        t = time.time()-t0
        if t > TIMEIT_THRESHOLD:
            self.logger.debug(f"TIMEIT {time.time()-t0:.4f} seconds")
        return table_name, parsed_rows


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
        if not isinstance(data, dict):
            raise ValueError("data is not a dictionary")
        self.logger = logger
        self.data = data

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
    link_name is key MUST be unique
    the link_name should be generated using get_link_name() function
    the bird command function is also here
    """
    # TODO: we have three types of link: native bgp, modified bgp and grpc

    def __init__(self, data, agent, logger=None):
        super(LinkManager, self).__init__(data, logger)
        self._send_buff = queue.Queue()
        self.bird_cmd_buff = queue.Queue()
        self.post_session = requests.Session()
        self.result_buff = {}
        self._job_id = 0
        self._add_lock = False
        self.agent = agent
        self.read_brd_cfg(agent.config['local_as'])
        self.bird_man = BirdCMDManager(logger)

    def get_by_name(self, name):
        if not name in self.data["links"]:
            self.logger.debug(self.data)
            raise ValueError(f"link {name} not found")
        return self.data["links"][name]

    def update_config(self, config):
        self.config = config

    def put_send_async(self, msg):
        """
        supported type : ["http-post","grpc","quic","dsav"]
        timeout is in seconds, if set to 0, then will keep trying until sent
        "retry" is optional, if set, then will retry for the given times (default is 10)  
        """
        # check if msg is valid
        key_types = [("msg_type", str), ("data", dict), ("source_app", str),
                     ("timeout", int), ("store_rep", bool)]
        keys_types_check(msg, key_types)

        supported_type = ["http-post", "dsav"]

        if not msg["msg_type"] in supported_type:
            raise ValueError(
                f"unknown msg type {msg['msg_type']} / {supported_type}")
        supported_apps = ["rpdp_app", "passport_app"]
        if not msg["source_app"] in supported_apps:
            raise ValueError(
                f"unknown msg source_app {msg['source_app']} / {supported_apps}")
        msg["pkt_id"] = self._job_id
        msg["created_dt"] = time.time()
        self._send_buff.put(msg)
        self._job_id += 1
        # do not remove this line, will trigger the shoot
        self.logger.debug(f"send_trigger{self._send_buff.qsize()}")

    def put_send_sync(self, msg):
        """
        will return response
        """
        raise NotImplementedError

    def read_brd_cfg(self, my_asn):
        """
        read link meta from birdc config, call if needed
        """
        f = open("/usr/local/etc/bird.conf", "r")
        data = f.readlines()
        f.close()
        for i in range(len(data)):
            if data[i].startswith("protocol bgp savbgp"):
                data = data[i:]
                break
        temp = {}
        proto_name = None
        for l in data:
            l = l.strip()
            if l.startswith("protocol"):
                l = l.split(" ")
                proto_name = l[2]
                meta = {
                    "initial_broadcast": False,
                    "as4_session": True,
                    "protocol_name": proto_name,
                    "status": True  # faster
                }
                if "sav_inter" in l:
                    meta["link_type"] = "dsav"
                elif "basic" in l:
                    meta["link_type"] = "native_bgp"
                else:
                    self.logger.error(f"unknown link type: {l}")
                temp[proto_name] = meta
            elif l.startswith("local role"):
                l = l.split(" ")
                local_role = l[-1][:-1]
                temp[proto_name]["local_role"] = local_role
                match local_role:
                    case "peer":
                        temp[proto_name]["remote_role"] = local_role
                    case "provider":
                        temp[proto_name]["remote_role"] = "customer"
                    case "customer":
                        temp[proto_name]["remote_role"] = "provider"
            elif l.startswith("neighbor"):
                l = l.split(" ")
                temp[proto_name]["remote_ip"] = l[1]
                temp[proto_name]["remote_as"] = int(l[-1][:-1])
                is_inter = temp[proto_name]["remote_as"] != my_asn
                temp[proto_name]["is_interior"] = is_inter
            elif l.startswith("source address"):
                l = l.split(" ")
                temp[proto_name]["local_ip"] = l[-1][:-1]
            elif l.startswith("interface"):
                temp[proto_name]["interface_name"] = l.split("\"")[1]
        self.data["check_time"] = time.time()
        self.data["links"] = temp
        self.data["update_time"] = self.data["check_time"]

    def get_all_link_meta(self):
        result = copy.deepcopy(self.data["links"])
        return result

    def _update_metric(self, d, msg):
        send = d["send"]
        send["count"] += 1
        send["size"] += len(str(msg["data"]))
        send["time"] += msg["finished_dt"] - msg["schedule_dt"]
        send["wait_time"] += msg["schedule_dt"] - msg["created_dt"]
        if d["start"] is None:
            d["start"] = msg["created_dt"]
        d["end"] = msg["finished_dt"]
        return d

    def send_msg(self, msg):
        # self.logger.debug(msg)
        msg["schedule_dt"] = time.time()
        match msg["msg_type"]:
            case "http-post":
                sent = self._send_http_post(msg)
            case "dsav":
                self.bird_cmd_buff.put(msg["data"])
                try:
                    self.agent.bird_man.bird_cmd("call_agent")
                    sent = True
                except:
                    sent = False
            case "grpc":
                raise NotImplementedError
            case _:
                raise ValueError(f"unknown msg type {msg['type']}")
        msg["finished_dt"] = time.time()
        # update_metric
        match msg["source_app"]:
            case "rpdp_app":
                match msg["msg_type"]:
                    case "dsav":
                        temp = self._update_metric(
                            self.agent.rpdp_app.metric["dsav"], msg)
                        self.agent.rpdp_app.metric["dsav"] = temp
                    case _:
                        raise ValueError(f"unknown msg type {msg['type']}")
            case _:
                raise ValueError(f"unknown msg source_app {msg['source_app']}")
        if not sent:
            self.logger.warning(f"send failed {msg}")
            self.send_buff.append(msg)

    def _send_http_post(self, msg):
        if msg["timeout"] == 0:
            while True:
                rep = self.post_session.post(
                    msg["url"], json=msg["data"], timeout=3)
                if rep.status_code == 200:
                    if msg["store_rep"]:
                        self.result_buff[msg["pkt_id"]] = rep.json()
                    return True
        if not "retry" in msg:
            retry = 10
        for i in range(retry):
            rep = self.post_session.post(
                msg["url"], json=msg["data"], timeout=msg["timeout"])
            if rep.status_code == 200:
                self.result_buff[msg["pkt_id"]] = rep.json()
                return True
            time.sleep(msg["timeout"])
        return False

    def add(self, meta_dict):
        self._is_good_meta(meta_dict)
        # self.logger.debug(f"adding {meta_dict}")
        link_type = meta_dict["link_type"]
        link_name = self._get_link_name(meta_dict)
        # self.logger.debug(f"adding {link_name}")
        if link_name in self.data:
            self.logger.warning(f"key {link_name} already exists")
            return
        if not link_type in ["native_bgp", "dsav"]:
            self.logger.error(f'unknown link_type: {link_type}')
            return
        self.data[link_name] = meta_dict
        self.logger.debug(f"link added: {link_name}")

    def _get_link_name(self, meta_dict):
        return meta_dict["protocol_name"]

    def update_link(self, meta_dict):
        self._is_good_meta(meta_dict)
        link_name = self._get_link_name(meta_dict)
        old_meta = self.data[link_name]
        if old_meta["status"] == meta_dict["status"]:
            return
        self.data[link_name] = meta_dict
        self.logger.debug(f"link updated: {self.data[link_name]} ")

    def rpdp_links(self, link_map):
        """return a list of link_name and link_data tuple that are rpdp links
        """
        results = []
        for link_name, link in self.data.items():
            # self.logger.debug(link["protocol_name"] )
            # self.logger.debug(link_map.keys() )
            if link["protocol_name"] in link_map:
                results.append((link_name, link))
            elif link["link_type"] == "dsav":
                results.append((link_name, link))
            else:
                self.logger.debug(f"ignoring no sav link: {link_name}")
        return results

    def get_all_up(self, include_native_bgp=False):
        """
        return a list of all up link_names ,use get(link_name) to get link object
        """
        temp = []
        for link_name, link in self.data["links"].items():
            self.logger.debug(link)
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
            if self.data["links"][link_name]["is_interior"] == is_interior:
                result.append(link_name)
        return result

    def get_bgp_by_interface(self, interface_name):
        """
        return a list of bgp(modified or native) link_dict that has the same interface_name
        """
        result = []
        # self.logger.debug(self.data)
        for _, link in self.data.items():
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
                     ("protocol_name", str), ("as4_session", bool),
                     ("is_interior", bool), ("status", bool),
                     ("initial_broadcast", bool)]
        keys_types_check(meta, key_types)
        if not meta["link_type"] in ["native_bgp", "dsav"]:
            raise ValueError(f'unknown link_type: {meta["link_type"]}')
        return True

    def _run(self):
        self.logger.debug("link manager started")
        """
        run in a separate thread, send msg in the send_buff
        """
        while True:
            msg = self._send_buff.get()
            # self.logger.debug(msg)
            self.send_msg(msg)
    def update_link_kv(self, link_name, k, v):
        self.data["links"][link_name][k] = v
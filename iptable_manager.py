#!/usr/bin/python3
# -*- encoding: utf-8 -*-
'''
@Time    :   2023/01/17 16:04:22
'''
import subprocess
from model import db
from model import SavInformationBase

KEY_WORD = "SAVAGENT"


def iptables_command_execute(sender, prefix, neighbor_as, interface, **extra):
    add_rule_status = subprocess.call(
        ['iptables', '-A', KEY_WORD, '!', '-i', interface, '-s', prefix, '-j', 'DROP'])
    print(add_rule_status)


class IPTableManager():
    """
    manage the SIB with SQLite and Flask-SQLAlchemy
    generate iptables rules and apply them
    """

    def __init__(self, app, logger):
        self.app = app
        create_chain_status = subprocess.call(['iptables', '-N', KEY_WORD])
        if create_chain_status != 0:
            return
        self.input_status = subprocess.call(
            ['iptables', '-I', 'INPUT', '-j', KEY_WORD])
        self.forward_status = subprocess.call(
            ['iptables', '-I', 'FORWARD', '-j', KEY_WORD])
        self.logger = logger
        db.drop_all()
        db.create_all()

    def _command_executer(self, command):
        return subprocess.run(command,
                              shell=True, capture_output=True, encoding='utf-8')

    def _get_host_interface_list(self):
        """
        return a list of 'clean' interface names
        """
        command = "ip link|grep -v 'link' | grep -v -E 'docker0|lo' | awk -F: '{ print $2 }' | sed 's/ //g'"
        command_result = self._command_executer(command=command)
        std_out = command_result.stdout
        # self.logger.debug(command_result)
        result = std_out.split("\n")[:-1]
        result = list(map(lambda x: x.split('@')[0], result))
        return result

    def _iptables_command_execute(self, command):
        command_result = self._command_executer(command=command)
        return command_result.returncode

    def add(self, data):
        """
        add a rule to the SIB
        currently only add ipv4 and inter-domain rules
        """
        prefix, src_app, interface = data.get(
            "prefix"), data.get("source_app"), data.get("interface")
        if (prefix is None) or (src_app is None) or (interface is None):
            self.logger.error(f"Missing required fields [{data.keys()}]")
            raise Exception("Missing required field")
        neighbor_as = data.get("neighbor_as")
        interface_list = self._get_host_interface_list()
        interface_list.append("*")
        if interface not in interface_list:
            self.logger.error(
                f"the interface {interface} doesn't exit in the list:{interface_list}")
            raise Exception("the interface doesn't exit!!")
        session = db.session
        if session.query(SavInformationBase).filter(
                SavInformationBase.prefix == prefix,
                SavInformationBase.interface == interface).count() != 0:
            self.logger.warning("rule exists")

            log_msg = f"SAV RULE EXISTS: {data}"
            # log_msg = f"SAV RULE EXISTS: prefix [{prefix}] can only comes from "
            # log_msg += f"interface_name [{interface}], remote_as [{neighbor_as}]"
            self.logger.info(log_msg)
            return
        if session.query(SavInformationBase).filter(
                SavInformationBase.prefix == prefix).count() == 0:
            interface_list.remove(interface)
            for drop_interface in interface_list:
                command = f"iptables -A {KEY_WORD} -i {drop_interface} -s {prefix} -j DROP"
                self._iptables_command_execute(command=command)
        else:
            command = f"iptables -L -v -n --line-numbers | grep {interface} | grep {prefix}"
            command += "| awk '{ print $1 }' | xargs - I v1  iptables - D "
            command += f"{KEY_WORD} v1"
            self._iptables_command_execute(command=command)
        # store data to DB
        sib_row = SavInformationBase(
            prefix=prefix,
            neighbor_as=neighbor_as,
            interface=interface,
            source=src_app,
            direction=None)
        session.add(sib_row)
        session.commit()
        session.close()
        log_msg = f"SAV RULE ADDED: {data}"
        # prefix [{prefix}] can only comes from "
        # log_msg += f"interface_name [{interface}], remote_as [{neighbor_as}]"
        self.logger.info(log_msg)

    def delete(self, input_id):
        session = db.session
        sib_row = session.query(SavInformationBase).filter(
            SavInformationBase.id == input_id).first()
        prefix, interface = sib_row.prefix, sib_row.interface
        session.delete(sib_row)
        session.commit()
        if session.query(SavInformationBase).filter(
                SavInformationBase.prefix == prefix).count() == 0:
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
        sib_tables = session.query(SavInformationBase).all()
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

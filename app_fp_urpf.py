import subprocess
from sav_common import *


class FpUrpfApp(SavApp):
    """
    a SAV App implementation based on modified bird
    """

    def __init__(self, agent, name="fpurpf_app", logger=None):
        super(FpUrpfApp, self).__init__(agent, name, logger)
        self.rules = {}

    def _init_protocols(self):
        result = self._parse_sav_protocols()
        while result == {}:
            time.sleep(0.1)
            result = self._parse_sav_protocols()
        self.protocols = result

    def _parse_sav_protocols(self):
        """
        using 'birdc show protocols' to get bird protocols
        """
        data = self._bird_cmd(cmd="show protocols")
        if data is None:
            return {}
        data = data.split("\n")
        while "" in data:
            data.remove("")
        result = []
        for row in data:
            protocol_name = row.split("\t")[0].split(" ")[0]
            if protocol_name.startswith("sav"):
                result.append(protocol_name)
        return result

    def _table_to_rules(self, table):
        """
        convert table to rules
        """
        result = []
        for as_number in table:
            for prefix in table[as_number]["prefixes"]:
                for interface_name in table[as_number]["interface_names"]:
                    result.append(sav_rule_tuple(
                        prefix, interface_name, self.name, as_number))
        return result

    def _bird_cmd(self, cmd):
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
            self.logger.error(f"birdc execute error:{out}")
            return None
        out = "\n".join(out.split("\n")[1:])
        return out

    def _parse_bird_fib(self):
        """
        using birdc show all to get bird fib
        """
        data = self._bird_cmd(cmd="show route all")
        if data is None:
            return {}
        data = data.split("Table")
        while "" in data:
            data.remove("")
        result = {}
        for table in data:
            table_name, table_data = parse_bird_table(
                table, self.logger)
            result[table_name] = table_data
        # self.logger.debug(result)
        return result

    def fib_changed(self):
        """
        fib change detected
        """
        # self._init_protocols()
        new_ = self._parse_bird_fib()

        if not "master4" in new_:
            self.logger.warning(
                "no master4 table. Is BIRD ready?")
            return [], []
        old_rules = self.rules
        new_ = new_['master4']
        # we need prefix-interface table
        for prefix in new_:
            # self.logger.debug(f"prefix:{prefix}:{new_[prefix]}")
            temp = []
            for item in new_[prefix]:
                temp.append(item["interface_name"])
            new_[prefix] = temp
        # self.logger.debug(f"new_:{new_}")
        # self.logger.debug(f"old_rules:{old_rules}")
        add_rules = []
        del_rules = []
        for prefix in new_:
            if prefix in old_rules:
                for interface_name in new_[prefix]:
                    if not interface_name in old_rules[prefix]:
                        add_rules.append(sav_rule_tuple(
                            prefix, interface_name, self.name))
                for interface_name in old_rules[prefix]:
                    if not interface_name in new_[prefix]:
                        del_rules.append(sav_rule_tuple(
                            prefix, interface_name, self.name))
            else:
                for interface_name in new_[prefix]:
                    add_rules.append(sav_rule_tuple(
                        prefix, interface_name, self.name))
        for prefix in old_rules:
            if not prefix in new_:
                for interface_name in old_rules[prefix]:
                    del_rules.append(sav_rule_tuple(
                        prefix, interface_name, self.name))
        self.rules = new_
        # self.logger.debug(f"add_rules:{add_rules}")
        # self.logger.debug(f"del_rules:{del_rules}")
        return add_rules, del_rules

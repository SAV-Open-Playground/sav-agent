# -*-coding:utf-8 -*-
"""
@File    :   app_urpf.py
@Time    :   2023/07/24
@Version :   0.1

@Desc    :   the app_urpf.py is responsible for uRPF-SAV rule generation (Strict and Loose)
"""

from common.sav_common import *
STRICT_URPF_ID = "strict_urpf"
LOOSE_URPF_ID = "loose_urpf"
class UrpfApp(SavApp):
    """
    a SavApp implementation of uRPF
    strict, loose
    """

    def __init__(self, agent, name="_urpf_app", mode="strict", logger=None):
        valid_modes = ["strict", "loose"]
        if mode not in valid_modes:
            raise ValueError(f"mode must be one of {valid_modes}")
        self.mode = mode
        super(UrpfApp, self).__init__(agent, name, logger)

    def generate_sav_rules(self,fib_adds, fib_dels, bird_fib_change_dict):
        """
        generate sav rule based on the latest fib,
        only add is implemented
        """
        # new_fib = self._get_cur_kernel_fib()
        if self.mode == "strict":
            return self._gen_rules(fib_adds, fib_dels, False)
        elif self.mode == "loose":
            return self._gen_rules(fib_adds, fib_dels, True)

    def _gen_rules(self, fib_adds, fib_dels, bird_fib_change_dict,is_loose=False):
        """
        generate sav rule based on the latest fib
        return a list of deleted rules and a dict of new rules
        """
        add_dict = {}
        del_list = []
        for prefix, row in fib_adds.items():
            face = "*"
            if not is_loose:
                face = row.get("Iface")
            this_rule = get_sav_rule(prefix, face, self.app_id)
            add_dict[get_key_from_sav_rule(this_rule)] = this_rule
        for prefix, row in fib_dels.items():
            face = "*"
            if not is_loose:
                face = row.get("Iface")
            this_rule = get_sav_rule(prefix, face, self.app_id)
            del_list.append(get_key_from_sav_rule(this_rule))
        return add_dict,del_list
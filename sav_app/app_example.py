from common import *

Example_ID = "example"
LOOSE_URPF_ID = "loose_urpf"


class Example(SavApp):
    """
    a SavApp implementation of uRPF
    strict, loose
    strict: if we see a prefix in fib, we ONLY allow it coming from the next hop in fib
    loose: if we see a prefix in fib, we allow it coming from any interface
    """

    def __init__(self, agent, name, logger=None):
        super(Example, self).__init__(agent, name, logger)
        self.ifa_map = {
            "inter": {
                "provider": NOT_SPECIFIED,
                "customer": NOT_SPECIFIED,
                "peer": NOT_SPECIFIED},
            "intra": NOT_SPECIFIED}

    def generate_sav_rules(self, fib_adds, fib_dels, old_rules):
        """
        generate sav rule based on the latest fib,
        only add is implemented
        """
        if self.mode == "strict":
            return self._gen_rules(fib_adds, fib_dels, is_loose=False)
        elif self.mode == "loose":
            return self._gen_rules(fib_adds, fib_dels, is_loose=True)

    def _get_one_rule(self, prefix, row, is_loose=False):
        """
        find the correct interface name for the sav rule generation
        return a sav rule
        """
        face = "*"
        if not is_loose:
            # self.logger.debug(row)
            if prefix.version == 4:
                face = row.get("Iface")
            elif prefix.version == 6:
                face = row.get("Use")
            else:
                raise ValueError(f"unknown ip version {prefix.version}")
        return get_sav_rule(prefix, face, self.app_id)

    def _gen_rules(self, fib_adds, fib_dels, is_loose=False):
        """
        generate sav rule based on the latest fib
        return a list of deleted rules and a dict of new rules
        """
        add_dict = {}
        del_list = []
        for prefix, row in fib_adds.items():
            this_rule = self._get_one_rule(prefix, row, is_loose)
            add_dict[get_key_from_sav_rule(this_rule)] = this_rule
        for prefix, row in fib_dels.items():
            this_rule = self._get_one_rule(prefix, row, is_loose)
            del_list.append(get_key_from_sav_rule(this_rule))
        return add_dict, del_list

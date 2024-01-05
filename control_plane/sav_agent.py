# -*-coding:utf-8 -*-
"""
@File    :   sav_agent.py
@Time    :   2023/01/10
@Version :   0.2
@Desc    :   the sav_agent.py 
This is a benchmark to test the performance of BIRD
"""

import copy
import sys
import threading
from common.logger import LOGGER
from control_plane.managers import *
from sav_app.app_rpdp import RPDPApp
from sav_app.app_urpf import UrpfApp
from sav_app.app_efp_urpf import EfpUrpfApp
from sav_app.app_fp_urpf import FpUrpfApp
from sav_app.app_bar import BarApp
from sav_app.app_passport import PassportApp
from data_plane.data_plane_enable import interceptor


def add_path(given_asn_path, data_dict):
    for path in data_dict:
        given_len = len(given_asn_path)
        saved_len = len(path)
        if given_len <= saved_len:
            if given_asn_path == path[:given_len]:
                return
    data_dict.append(given_asn_path)


def aggregate_asn_path(list_of_asn_path):
    temp = []
    for path in list_of_asn_path:
        temp.append(path[list(path.keys())[0]])

    temp = sorted(temp, key=lambda x: len(x), reverse=True)
    result = {}
    for route in temp:
        if route[0] not in result:
            result[route[0]] = [route]
        else:
            add_path(route, result[route[0]])
    return result


class SendAgent():
    def __init__(self, agent, config, logger):
        """
        currently we don't handle the reply ()ignore, don't use if you need reply
        """


class SavAgent():
    def __init__(self, logger=None, path_to_config=os.path.join(
            os.path.dirname(os.path.abspath(__file__)), "SavAgent_config.json")):
        first_dt = time.time()
        if logger is None:
            logger = LOGGER
        self.logger = logger
        self.config = {}
        self.link_man = None
        self.update_config(path_to_config)
        self._init_data(first_dt)
        self._in_msgs = queue.Queue()
        self._init_apps()
        # self.sib_man = s(logger=self.logger)
        # self.sib_man.upsert("config", json.dumps(self.config))
        # self.sib_man.upsert("active_app", json.dumps(self.data["active_app"]))
        self.bird_man = BirdCMDManager(logger=self.logger)
        self._start()

        # self.grpc_server = None

    def put_out_msg(self, msg):
        # self.logger.debug(f"putting out msg {msg}")
        self.link_man.put_send_async(msg)

    def update_config(self, path_to_config):
        """
        return dictionary object if is a valid config file (only check type not value). 
        Otherwise, raise ValueError
        we should ALWAYS check self.config for latest values
        """
        for _ in range(3):
            try:
                config = read_json(path_to_config)
                required_keys = [
                    ("apps", list), ("grpc_config", dict), ("location", str),
                    ("quic_config", dict), ("link_map", dict), ("local_as", int)]
                keys_types_check(config, required_keys)

                grpc_config = config["grpc_config"]
                grpc_keys = [("server_addr", str), ("server_enabled", bool)]
                keys_types_check(grpc_config, grpc_keys)

                quic_config = config["quic_config"]
                grpc_keys = [("server_enabled", bool)]
                keys_types_check(quic_config, grpc_keys)

                valid_location = ["edge_full", "internal", "gray"]
                temp = {}
                for p in config["prefixes"]:
                    temp[netaddr.IPNetwork(p)] = config["prefixes"][p]
                config["prefixes"] = temp
                if not config["location"] in valid_location:
                    raise ValueError(
                        f"invalid location {config['location']}, should be one of {valid_location}")
                self.config = config
                return
            except Exception as e:
                self.logger.debug(e)
                self.logger.exception(e)
                self.logger.error("invalid config file ,retry {i}")
                time.sleep(0.1)
        raise ValueError("invalid config file")

    def send_msg_to_agent(self, msg, link):
        """
        send message to another agent
        currently, only rpdp will sent to agent
        """
        # using grpc
        self.logger.error(msg)
        self.logger.error(link)
        raise NotImplementedError

    def _init_data(self, first_dt):
        """
        all major data should be initialized here
        """
        self.data = {}
        self.data["metric"] = init_protocol_metric()
        self.data["metric"]["first_dt"] = first_dt
        self.data["metric"]["initial_fib_stable"] = False
        self.data["metric"]["is_fib_stable"] = False
        self.data["metric"]["skipped_bgp_update"] = 0
        self.data["pkt_id"] = 0
        self.data["msg_count"] = 0
        self.data["links"] = {}  # link manager"s data
        self.data["fib"] = []  # system"s fib table
        # key is prefix (str), value is as paths in csv
        self.data["sav_table"] = {}
        # node key is as number, value is None; link key is as number,
        # value is list of directly connected as numbers, link is undirected
        self.data["sav_graph"] = {"nodes": {}, "links": {}}
        self.link_man = LinkManager(
            self.data["links"], self, logger=self.logger)
        self.data["apps"] = {}
        self.data["kernel_fib"] = {"data": parse_kernel_fib(),
                                   "update_time": time.time(),
                                   "check_time": time.time()}
        self.data["fib_for_apps"] = {}
        

    def add_sav_nodes(self, nodes):
        data = self.data["sav_graph"]["nodes"]
        added = False
        for node in nodes:
            if not node in data:
                data[node] = None
                # self.logger.info(f"SAV GRAPH NODE ADDED :{node}")
                added = True
        if added:
            # self.sib_man.upsert(
            #     "sav_graph", json.dumps((self.data["sav_graph"])))
            pass

    def add_sav_link(self, asn_a, asn_b):
        data_dict = self.data["sav_graph"]
        asn_a = int(asn_a)
        asn_b = int(asn_b)
        self.add_sav_nodes([asn_a, asn_b])
        if asn_a == asn_b:
            return
        # add link if not exist
        key_asn = min(asn_a, asn_b)
        value_asn = max(asn_a, asn_b)
        if not key_asn in data_dict["links"]:
            data_dict["links"][key_asn] = [value_asn]
            # self.sib_man.upsert("sav_graph", json.dumps((data_dict)))
            self.logger.info(f"SAV GRAPH LINK ADDED :{key_asn}-{value_asn}")
            return
        # now key_asn in data_dict["links"]
        if value_asn not in data_dict["links"][key_asn]:
            data_dict["links"][key_asn].append(value_asn)
            # self.sib_man.upsert("sav_graph", json.dumps((data_dict)))
            self.logger.info(f"SAV GRAPH LINK ADDED :{key_asn}-{value_asn}")

    def _init_apps(self):
        # bird and grpc are must
        self.rpdp_app = None
        self.passport_app = None
        self.data["active_app"] = None
        # self.logger.debug(self.config)
        if len(self.config["apps"]) == 0:
            self.logger.warning("no sav app given")
        for name in self.config["apps"]:
            if name == "strict-uRPF":
                app_instance = UrpfApp(
                    self, mode="strict", logger=self.logger)
                self.add_app(app_instance)
            elif name == "loose-uRPF":
                app_instance = UrpfApp(
                    self, mode="loose", logger=self.logger)
                self.add_app(app_instance)
            elif name.startswith("EFP-uRPF"):
                app_instance = EfpUrpfApp(
                    self, name, self.logger, self.config.get("ca_host"), self.config.get("ca_port", 3000))
                self.add_app(app_instance)
            elif name == "FP-uRPF":
                app_instance = FpUrpfApp(self, logger=self.logger)
                self.add_app(app_instance)
            elif name == "rpdp_app":
                app_instance = RPDPApp(self, logger=self.logger)
                self.add_app(app_instance)
                self.rpdp_app = app_instance
            elif name == "bar_app":
                app_instance = BarApp(self, logger=self.logger)
                self.add_app(app_instance)
            elif name == "passport":
                app_instance = PassportApp(
                    self, self.config["local_as"], self.config["router_id"], logger=self.logger)
                self.passport_app = app_instance
                self.add_app(app_instance)

            else:
                self.logger.error(msg=f"unknown app name: {name}")
            if self.config["enabled_sav_app"] == name:
                self.data["active_app"] = app_instance.name
        self.logger.debug(
            msg=f"initialized apps: {list(self.data['apps'].keys())},using {self.data['active_app']}")

    def _refresh_kernel_fib(self, filter_base=True):
        """
        update kernel fib
        tell if kernel fib stable
        return new_fib, adds, dels
        """
        new_ = parse_kernel_fib()
        if filter_base:
             # TODO read from config
            remove_prefixes = [netaddr.IPNetwork("1.1.0.0/16")]
            temp = {}
            for prefix in new_:
                keep = True
                for p in remove_prefixes:
                    if prefix in p:
                        keep = False
                        break
                if keep:
                    temp[prefix] = new_[prefix]
            new_ = temp
        # self.logger.debug(new_)
        # for prefix in new_:
        # self.logger.debug(f"{prefix}:{new_[prefix]}")
        if len(new_) == 0:
            self.logger.error("kernel fib empty")
        t0 = time.time()
        old_ = self.data["kernel_fib"]["data"]
        # self.logger.debug(old_)
        self.data["kernel_fib"]["check_time"] = t0
        adds = {}
        dels = {}
        for prefix in new_:
            if "Met" in new_[prefix]:
                del new_[prefix]["Met"]
            if "Metric" in new_[prefix]:
                del new_[prefix]["Metric"]
            if old_.get(prefix, None) != new_[prefix]:
                adds[prefix] = new_[prefix]
        for prefix in old_:
            if new_.get(prefix, None) != old_[prefix]:
                dels[prefix] = old_[prefix]
        fib_changed = False
        if len(adds) + len(dels) > 0 or len(new_) == 0:
            self.data["kernel_fib"]["update_time"] = t0
            self.data["kernel_fib"]["data"] = new_
            self.logger.debug(f"kernel fib changed")
            self.logger.debug(f"adds:{adds}")
            self.logger.debug(f"dels:{dels}")
            fib_changed = True
        fib_update_dt = self.data["kernel_fib"]["update_time"]
        if fib_changed:
            self.data["metric"]["is_fib_stable"] = False

        if t0 - fib_update_dt > self.config["fib_stable_threshold"]:
            if not self.data["metric"]["is_fib_stable"]:
                self.data["metric"]["is_fib_stable"] = True
                self.data["metric"]["last_fib_stable_dt"] = fib_update_dt
                self.logger.debug(f"FIB stable at {fib_update_dt}")
                if not self.data["metric"]["initial_fib_stable"]:
                    self.data["metric"]["initial_fib_stable"] = True
                    self.data["metric"]["initial_fib_stable_dt"] = fib_update_dt
        if self.data["metric"]["is_fib_stable"]:
            # pass
            self.bird_man.update_fib(self.config["local_as"])
        return self.data["kernel_fib"]["data"], adds, dels


    def _initial_wait(self, check_span=0.1):
        """
        1. wait for bird to be ready
        2. wait for fib to be stable
        3. perform initial events(send spa)
        """
        while not self.bird_man.is_bird_ready():
            time.sleep(check_span)
            # self.logger.debug("waiting for bird to be ready")
        while not self.data["metric"]["initial_fib_stable"]:
            # wait for fib to first fib stable
            self._refresh_kernel_fib()

            time.sleep(check_span)
        if self.rpdp_app:
            self.rpdp_app.send_spa_init()
            self.logger.debug("spa init sent")
        return

    def is_all_msgs_finished(self):
        """
        check if all msgs are finished
        """
        ret = self._in_msgs.all_tasks_done()
        return ret

    def _add_pkt_id(self, msg):
        self.data["pkt_id"] += 1
        msg["pkt_id"] = self.data["pkt_id"]
        return msg

    def _precheck_msg(self, msg, bgp_update_msg, msgs):
        """
        aggregate native bgp update msg
        """
        if msg["msg_type"] == "bgp_update":
            if bgp_update_msg is None:
                msg = self._add_pkt_id(msg)
                bgp_update_msg = msg
            else:
                # self.logger.debug("skipping native bgp update")
                self.data["metric"]["skipped_bgp_update"] += 1
                self._in_msgs.task_done()
        else:
            msg = self._add_pkt_id(msg)
            msgs.append(msg)
        return bgp_update_msg, msgs

    def _run(self):
        """
        start a thread to check the cmd queue and process each cmd
        """
        self._initial_wait()
        # self.logger.debug("starting main loop")
        while True:
            try:
                try:
                    msgs = []
                    # we first detect all native bgp update,
                    # if we detect one native bgp update, we insert a msg to trigger the kernel fib update
                    bgp_update_msg = None
                    msg0 = self._in_msgs.get()
                    bgp_update_msg, msgs = self._precheck_msg(
                        msg0, bgp_update_msg, msgs)
                    # self.logger.debug(self._in_msgs.qsize())
                    for _ in range(self._in_msgs.qsize()):
                        msg = self._in_msgs.get()
                        bgp_update_msg, msgs = self._precheck_msg(
                            msg, bgp_update_msg, msgs)
                    if bgp_update_msg:
                        msgs = [bgp_update_msg] + msgs
                    for m in msgs:
                        # self.logger.debug(f"processing msg {m}")
                        self._process_msg(m)
                        self._in_msgs.task_done()
                except Exception as err:
                    self.logger.exception(err)
                    self.logger.error(
                        f"error when processing: [{err}]")
                while self.link_man._send_buff.qsize() > 0:
                    msg = self.link_man._send_buff.get()
                    self.link_man.send_msg(msg)
                    self.link_man._send_buff.task_done()
            except Exception as e:
                self.logger.exception(e)
                self.logger.error(e)
                self.logger.error(type(e))

    def add_app(self, app):
        self.data["apps"][app.name] = app

    def get_app(self, name):
        return self.data["apps"][name]

    def get_all_app_names(self):
        return list(self.data["apps"].keys())

    def get_apps_by_type(self, app_class):
        """
        return a generator of apps that are instance of given app_class
        """
        for app in self.data["apps"].values():
            if isinstance(app, app_class):
                yield app

    def get_local_prefixes(self):
        """
        return a list of local prefixes
        """
        local_prefixes = list(self.bird_man.get_local_fib().keys())
        return local_prefixes

    def perf_test_send(self, ratio, nlri_num, total_pkt_num):
        raise NotImplementedError

    def put_msg(self, msg):
        """
        should only be called via link
        """
        key_types = [("msg_type", str), ("source_app", str),
                     ("source_link", str), ("pkt_rec_dt", float)]
        if not "msg" in msg:
            raise KeyError(f"msg missing in msg:{msg}")
        keys_types_check(msg, key_types)
        msg["created_dt"] = time.time()
        self._in_msgs.put(msg)

    def _process_link_state_change(self, msg):
        """
        in this function, we manage the link state
        """
        key_types = [("msg", bool), ("source_link", str)]
        keys_types_check(msg, key_types)
        new_state = msg["msg"]
        link_name = msg["source_link"]
        if not new_state:
            return  # ignore link down
        try:
            self.link_man.update_link_kv(link_name, "state", new_state)
        except KeyError:
            pass

        if self.passport_app:
            self.passport_app.init_key_publish()

    def _log_info_for_front(self, msg, log_type, link_name=None):
        """
        logging in specific format for front end, 
        this function will deepcopy msg and modify it for logging,so avoid using it in performance sensitive code
        """
        msg1 = None
        if msg is not None:
            msg1 = copy.deepcopy(msg)
            if "sav_nlri" in msg1:
                msg1["sav_nlri"] = list(map(str, msg1["sav_nlri"]))
            if "sav_origin" in msg1:
                while [] in msg1["sav_scope"]:
                    msg1["sav_scope"].remove([])
                msg1["sav_scope"] = list(
                    map(lambda x: list(map(int, x)), msg1["sav_scope"]))
        if log_type == "terminate":
            self.logger.info(f"TERMINATING: {msg1}")
        elif log_type == "sav_graph":
            self.logger.info(f"SAV GRAPH :{self.data['sav_graph']}")
        elif log_type == "got_msg":
            self.logger.info(
                f"GOT MSG ON  [{msg1['protocol_name']}]:{msg1}, time_stamp: [{time.time()}]")
        elif log_type == "relay_terminate":
            self.logger.info(
                f"RELAY TERMINATED MSG ON INTRA-LINK: {link_name}, msg:{msg1}")

    def _process_sav_intra(self, msg, link_meta):
        """
        doing nothing but logging
        """
        self.logger.info(
            f"GOT INTRA-MSG ON [{link_meta['protocol_name']}]:{msg}, time_stamp: [{time.time()}]")
        if link_meta["is_interior"]:
            self.logger.error("intra-msg received on inter-link!")

    def get_kernel_fib(self):
        """return the cached fib"""
        return self.data["kernel_fib"]["data"]

    def _process_native_bgp_update(self, reset=False):
        """
        the msg is not used here
        """
        return
        # _, adds, dels = self._refresh_kernel_fib()

        # if len(adds) == 0 and len(dels) == 0:
        # return
        # self.bird_man.update_fib(self.config["local_as"])
        # self._notify_apps(adds, dels, reset)
        # self.logger.debug(f"_notify_apps finished")

    def reset(self):
        self._process_native_bgp_update(True)

    def _notify_apps(self, adds, dels, reset, app_list=None):
        """
        rpdp logic is handled in other function
        here we pass the FIB change to SAV mechanism,
        who does not need other information
        """
        add_rules = []
        del_rules = []
        if app_list is None:
            app_list = self.get_all_app_names()
        for app_name in app_list:
            app = self.get_app(app_name)
            self.logger.debug(f"notifying app: {app_name}")
            a, d = [], []
            app_type = type(app)
            if app_type in [UrpfApp]:
                if len(adds) > 0 or len(dels) > 0:
                    a, d = app.fib_changed(adds, dels)
            elif app_type in [EfpUrpfApp, FpUrpfApp, BarApp, PassportApp]:
                a, d = app.fib_changed()
            elif app_type in [RPDPApp]:
                adds, dels = self.rpdp_app.diff_pp_v4(reset)
                self.logger.debug(f"adds:{len(adds)}")
                changed_routes = []
                for prefix, path in adds:
                    changed_routes.append({prefix: path})
                self.logger.debug(f"changed_routes:{changed_routes}")
                # self._send_origin(None, changed_routes)
            else:
                self.logger.error(f":{type(app)}")
            for rule in a:
                row = {"prefix":        rule[0],
                       "interface":     rule[1],
                       "source_app":    rule[2],
                       "neighbor_as":   rule[3]
                       }
                if rule[1] == "*":
                    up_link_names = self.link_man.get_all_up_type(True)
                    # TODO currently we only apply to bgp interfaces
                    for link_name in up_link_names:
                        link_dict = self.link_man.get_by_name(
                            link_name)
                        row["local_role"] = link_dict["local_role"]
                        add_rules.append(row)
                else:
                    temp = self.bird_man.get_bgp_by_interface(rule[1])
                    if temp == []:
                        self.logger.warning(
                            f"unable to find meta fo link {rule[1]}")
                        return
                    if len(temp) != 1:
                        self.logger.error(temp)
                        self.logger.error(
                            f"{len(temp)} bgp instances found on interface [{rule[1]}],")
                    temp = temp[0]
                    row["local_role"] = temp["local_role"]
                    add_rules.append(row)
            # TODO d
            del_rules.extend(d)
        # self.logger.debug(f"add_rules:{add_rules}")
        # self.logger.debug(f"del_rules:{del_rules}")
        self.update_sav_table(add_rules, del_rules)
        # self.ip_man.add(add_rules)

        return

    def update_sav_table(self, adds, dels):
        """
        update sav table, and notify apps
        adds and dels are list of sav rules
        """
        cur_t = time.time()
        new_table = copy.deepcopy(self.data["sav_table"])
        for r in dels:
            if not r["source_app"] in new_table:
                continue
            str_key = get_key_from_sav_rule(r)
            if not str_key in new_table[r["source_app"]]:
                self.logger.error(
                    f"key missing in sav_table (old):{r}/{str_key}")
            else:
                del new_table[r["source_app"]][str_key]
                self.logger.info(f"SAV RULE DELETED:{r}")
        for r in adds:
            # self.logger.debug(r)
            if not r["source_app"] in new_table:
                new_table[r["source_app"]] = {}
            str_key = get_key_from_sav_rule(r)
            # self.logger.debug(str_key)
            if not str_key in new_table[r["source_app"]]:
                r["create_time"] = cur_t
                r["update_time"] = cur_t
                new_table[r["source_app"]][str_key] = r
                self.logger.info(f"SAV RULE ADDED:{r}")
            else:
                old_value = new_table[r["source_app"]][str_key]
                r["create_time"] = old_value['create_time']
                r["update_time"] = old_value['update_time']
                if not r == old_value:
                    self.logger.error(
                        f"conflict in sav_table (old):{old_value}")
                    self.logger.error(f"conflict in sav_table (new):{r}")
                r["update_time"] = cur_t
                new_table[r["source_app"]][str_key] = r
                self.logger.info(f"SAV RULE REFRESHED:{r}")
        self.data["sav_table"] = new_table

    def update_sav_table_by_app_name(self, add_dict, del_set, source_app):
        """
        update sav table
        """
        cur_t = time.time()
        if not source_app in self.data["sav_table"]:
            new_table = {}
        new_table = copy.deepcopy(self.data["sav_table"][source_app])
        for str_key in del_set:
            if not str_key in new_table:
                self.logger.error(
                    f"key missing in sav_table (old):{str_key} in {new_table.keys()}")
            else:
                r = new_table[str_key]
                del new_table[str_key]
                self.logger.info(f"SAV RULE DELETED:{r}")
        for str_key, r in add_dict.items():
            if not str_key in new_table:
                r["create_time"] = cur_t
                r["update_time"] = cur_t
                new_table[str_key] = r
                self.logger.info(f"SAV RULE ADDED:{r}")
            else:
                old_r = new_table[str_key]
                r["create_time"] = old_r['create_time']
                r["update_time"] = old_r['update_time']
                if r == old_r:
                    self.logger.error(
                        f"conflict in sav_table (old):{old_r}")
                    self.logger.error(f"conflict in sav_table (new):{r}")
                else:
                    r["update_time"] = cur_t
                new_table[str_key] = r
                self.logger.info(f"SAV RULE REFRESHED:{r}")
        self.data["sav_table"][source_app] = new_table

    def get_sav_rules_by_app(self, app_name, is_interior=None):
        """
        return all sav rules for given app
        if is_interior is None, return all rules
        if is_interior is True, return all interior rules
        if is_interior is False, return all exterior rules
        """
        if not app_name in self.data["sav_table"]:
            self.data["sav_table"][app_name] = {}
            return {}
        all_rules = self.data["sav_table"][app_name]
        if is_interior is None:
            return all_rules
        temp = {}
        for k, v in all_rules.items():
            if v["is_interior"] == is_interior:
                temp[k] = v
        return temp

    def _find_links_for_origin(self, input_link_name):
        inter_links = []
        intra_links = []
        if input_link_name is None:
            # when sending origin, we send to all links
            up_links = self.link_man.get_all_link_meta()
            # pre checking
            if len(up_links) == 0:
                self.logger.debug("no link is up, not sending")
                return False
            for link_name, meta in up_links.items():
                if meta["is_interior"]:
                    inter_links.append((link_name, meta))
                else:
                    intra_links.append((link_name, meta))
        else:
            meta = self.link_man.get_by_name(input_link_name)
            if meta["is_interior"]:
                inter_links.append((input_link_name, meta))
            else:
                intra_links.append((input_link_name, meta))
        return inter_links, intra_links

    def _find_paths_for_origin(self, input_paths):
        intra_paths = []
        inter_paths = []
        if input_paths is None:
            pp = self.bird_man.get_remote_fib()
            self.logger.debug(f"pp:{pp}")
            for prefix in pp:
                for path in pp[prefix]["as_path"]:
                    inter_paths.append({prefix: path})
                # prepare data for inter-msg TODO: intra-msg broadcast
        else:
            # self.logger.debug(input_paths)
            for path in input_paths:
                for prefix in path:
                    path_data = list(map(str, path[prefix]))
                    # transform the data first
                    # self.logger.debug(",".join(path_data))
                    path_str = ",".join(path_data)
                    if len(path_str) == 0:
                        self.logger.warning(
                            f"empty path for prefix [{prefix}], not sending")
                        continue
                    if tell_str_is_interior(",".join(path_data)):
                        inter_paths.append(path)
                    else:
                        intra_paths.append(path)
        # self.logger.debug(f"intra_paths:{intra_paths}")
        # self.logger.debug(f"inter_paths:{inter_paths}")
        # temp = []
        # self.logger.debug(len(inter_paths))
        # for i in inter_paths:
        #     for k,v in i.items():
        #         if not k.is_private():
        #             temp.append({k:v})
        # inter_paths = temp

        inter_paths = aggregate_asn_path(inter_paths)
        self.logger.debug(inter_paths)
        # self.logger.debug(f"inter_paths:{inter_paths}")

        return inter_paths, intra_paths

    def _build_addresses_for_spd(self, remote_prefixes, links):
        ret = {}
        for link_name in links:
            ret[links[link_name]['remote_ip']] = []
        for prefix, prefix_data in remote_prefixes.items():
            if not prefix_data["remote_ip"] in ret:
                self.logger.error(
                    f"remote_ip {prefix_data['remote_ip']} not in links")
                continue
            self.logger.debug(f"{prefix}:{prefix_data}")
            ret[prefix_data["remote_ip"]].append(prefix)
        for k in ret:
            ret[k] = prefixes2addresses(ret[k])
        return ret

    def _send_origin(self, input_link_name=None, input_paths=None):
        """
        send origin messages,
        if input_link_name is None, send to all available links
        if input_paths is None, send all suitable prefixes
        """
        func_start = time.time()
        if self.rpdp_app is None:
            self.logger.debug("rpdp_app missing,unable to send origin")
            return True
        sent = False
        try:
            inter_links, intra_links = self._find_links_for_origin(
                input_link_name)
            inter_paths, intra_paths = self._find_paths_for_origin(input_paths)
            if len(inter_links) > 0 and len(inter_paths) > 0:
                # we send origin to all links no matter inter or intra
                for link_name, link in inter_links:
                    # generate msg for this link
                    remote_as = link["remote_as"]
                    if remote_as not in inter_paths:
                        # may happen when broadcasting, essentially is because the next as is not in the intended path,why?
                        # TODO
                        # self.logger.warning()
                        # self.logger.debug(f"inter_paths:{inter_paths}")
                        # self.logger.debug(f"remote_as:{remote_as}")
                        pass
                    else:
                        paths_for_as = inter_paths[remote_as]
                        # self.logger.debug(paths_for_as)
                        msg = self.rpdp_app._construct_msg(
                            link, paths_for_as, "origin", True)
                        if len(msg["sav_nlri"]) > 0:
                            # self.logger.warning(f"sent origin via inter{msg}")
                            self.send_msg_to_agent(msg, link)
                            sent = True
                        else:
                            self.logger.debug(
                                f"no sav nlri, not sending inter origin on link {link_name}")
            else:
                msg = f"no inter link:{len(inter_links)} or inter path:{len(inter_paths)}, not sending inter origin"
                # self.logger.debug(msg)
                return False
            if len(intra_links) > 0:
                self.logger.error("intra origin not implemented")
                for link in intra_links:
                    for remote_as, path in inter_paths.items():
                        msg = self.rpdp_app._construct_msg(
                            link, path, "origin", True)
                        # self.logger.debug(msg)
                        self.send_msg_to_agent(msg, link)
                        self.logger.debug(f"sent origin via intra{msg}")
                        # TODO intra origin
            t = time.time()-func_start
            if t > TIMEIT_THRESHOLD:
                self.logger.debug(f"TIMEIT {t:.4f} seconds")
            self.logger.debug(intra_paths)
            return sent
        except Exception as e:
            self.logger.exception(e)
            self.logger.error(e)
            return sent

    def _process_msg(self, input_msg):
        input_msg["schedule_dt"] = time.time()
        t0 = input_msg["schedule_dt"]
        # self.logger.debug(input_msg)
        log_msg = f"start msg, pkt_id:{input_msg['pkt_id']}, msg_type: {input_msg['msg_type']}"
        key_types = [("msg_type", str), ("pkt_id", int), ("pkt_rec_dt", float)]
        keys_types_check(input_msg, key_types)
        msg, m_t = input_msg["msg"], input_msg["msg_type"]
        # self.logger.debug(input_msg)
        match m_t:
            case "link_state_change":
                self._process_link_state_change(input_msg)
            case "bird_bgp_config":
                # TODO for faster performance
                pass
            case "bgp_update":
                self._process_native_bgp_update()
            case "rpdp_update":
                self.rpdp_app.process_rpdp_spa_msg(input_msg)
            case "rpdp_route_refresh":
                # self.logger.debug(f"got rpdp_route_refresh:{input_msg}")
                link_name = input_msg["source_link"]
                link_meta = self.link_man.get_by_name(link_name)
                self.rpdp_app.process_rpdp_route_refresh(input_msg, link_meta)
            case "grpc_msg":
                if self.rpdp_app:
                    self.rpdp_app.process_grpc_msg(input_msg)
            case "quic_msg":
                if self.rpdp_app:
                    self.rpdp_app.process_quic_msg(input_msg)
            case "perf_test":
                if self.rpdp_app:
                    self.rpdp_app.perf_test_send(
                        list(map(json.loads, msg)))
            case "passport_key_exchange":
                key = "key_exchange"
                self.passport_app.update_metric(
                    msg, key, False, True)
                self.passport_app.process_key_publish(input_msg)
                self.passport_app.update_metric(
                    msg, key, False, False, t0)
            case "passport_send_pkt":
                key = "pkt"
                self.passport_app.update_metric(
                    msg, key, True, True)
                target_ip = msg["target_ip"]
                self.passport_app.send_pkt(target_ip, msg["data"])
                self.passport_app.update_metric(
                    msg, key, True, False, t0)
            case "passport_recv_pkt":
                key = "pkt"
                self.passport_app.update_metric(
                    input_msg["msg"], key, False, True)
                self.passport_app.rec_pkt(input_msg)
                self.passport_app.update_metric(
                    input_msg["msg"], key, False, False, t0)
            case _:
                self.logger.warning(f"unknown msg type: [{m_t}]\n{input_msg}")
        t1 = time.time()
        # if m_t in ["quic_msg", "passport_pkt", "grpc_msg", "bgp_update"]:
        #     if len(input_msg["msg"]["sav_nlri"]) > 0:
        #         self.data["msg_count"] += 1
        #         self.logger.debug(
        #             f"PERF-TEST: got {m_t} packet ({self.data['msg_count']}) at {t0}")
        #         self.logger.debug(
        #             f"PERF-TEST: finished PROCESSING ({self.data['msg_count']}) at {t1}")
        if t1-t0 > TIMEIT_THRESHOLD:
            log_msg = log_msg.replace("start", "finish")
            log_msg += f", time used: {t1-t0:.4f}"
            self.logger.debug(log_msg)
        metric = self.data["metric"]["recv"]
        metric["count"] += 1
        metric["time"] += t1-t0
        # self.logger.debug(f", time used: {t1-t0:.4f}; msg:{input_msg}")
        metric["size"] += len(str(input_msg))
        # if not m_t.startswith("passport"):
        self._update_sav_rule_nums()
        # self.logger.debug(f"finished")

    def _update_sav_rule_nums(self):
        """
        update sav rule nums and print to log
        """
        metric = self.data["metric"].get("sav_rule_nums", {})
        old_metric = copy.deepcopy(metric)
        data = self.data["sav_table"]
        for app, rules in data.items():
            metric[f"{app}"] = {"sav_rule_num": len(rules)}
            metric[f"{app}"]["update_dt"] = 0
            for k, v in rules.items():
                if v["update_time"] > metric[f"{app}"]["update_dt"]:
                    metric[f"{app}"]["update_dt"] = v["update_time"]
            metric[f"{app}_rule_num"] = metric[f"{app}"]["sav_rule_num"]
        if not old_metric == metric:
            self.data["metric"]["sav_rule_nums"] = metric
            metric["total"] = 0
            for k, v in metric.items():
                if k.endswith("_rule_num"):
                    metric["total"] += v
            self.logger.debug(f"SAV RULE NUMS: {metric['total']}")
    def _get_spd_id(self,remote_as,remote_router_id):
        return f"{remote_as}-{remote_router_id.value}"

    def get_next_link_meta(self, target_ip):
        """
        find the meta for the given target_ip
        if not find we return None.
        raise Vale if a local ip is given
        """
        # self.logger.debug(f"target_ip:{target_ip}")
        try:
            link_meta = self.link_man.get_by_local_ip(target_ip)
            self.logger.error(link_meta)
            self.logger.error(target_ip)
            raise ValueError("target_ip is local")
        except ValueError:
            pass
        try:
            link_meta = self.link_man.get_by_remote_ip(target_ip)
            return link_meta
        except ValueError:
            pass
        # find in fib
        next_hop_ip = get_next_hop(target_ip)
        # self.logger.debug(next_hop_ip)
        try:
            link_meta = self.link_man.get_by_remote_ip(next_hop_ip)
            return link_meta
        except ValueError:
            self.logger.debug(f"next_hop_ip:{next_hop_ip}")
            self.logger.debug(f"target_ip:{target_ip}")
            return None
    def _send_spd(self):
        """
        build spd and send to all links
        """
        my_asn = self.config["local_as"]
        # self.logger.debug("sending spd")
        if self.rpdp_app is None:
            self.logger.debug("rpdp_app missing,unable to send spd")
            return False
        possible_prefixes = self.bird_man.get_remote_fib() # here the remote refers to prefixes that are not originated by this router
        inter_as_links = {}
        for link_name in self.link_man.get_all_up_type(True,False):
            inter_as_links[link_name] = self.link_man.get_by_name(link_name)
        
        
        temp = {}
        intra_as_links = {}
        my_as_prefixes = {}
        as_neighbors = {}
        # self.logger.debug(inter_as_links)
        # self.logger.debug(possible_prefixes)
        for prefix,srcs in possible_prefixes.items():
            # self.logger.debug(f"{prefix}:{srcs}")
            my_asn_prefix = False
            
            for src in srcs :
                if src["origin_asn"]==my_asn:
                    my_asn_prefix = True
                if not src["origin_asn"] in as_neighbors:
                    as_neighbors[src["origin_asn"]] = []
                t = src["type"]
                if not t == "BGP univ":
                    self.logger.error(f"unknown type:{t}")
                if "as_path" in src:
                    if my_asn in src["as_path"]:
                        x = src["as_path"].index(src["origin_asn"])
                        try:
                            as_neighbors[src["origin_asn"]].append(src["as_path"][x+1])
                        except IndexError:
                            pass
                        try:
                            as_neighbors[src["origin_asn"]].append(src["as_path"][x-1])
                        except IndexError:
                            pass
            if my_asn_prefix:
                my_as_prefixes[prefix] = srcs
                
        # TODO add logic to find neighbors
            
      
        self.rpdp_app.send_spd(inter_as_links
                               , as_neighbors
                               ,my_as_prefixes
                               ,self.config["local_as"]
                               ,self.config["router_id"])
        # for p, d in remote_prefixes.items():
        #     link_meta = 
        #     is_inter = link_meta["is_interior"]
        #     if not is_inter:
        #         self.logger.error("attempt to send spd on intra-link for a inter-prefix,skipping")
        #         continue
        #     neighbor_as = d["as_path"]
        #     for i in [self.config["local_as"]]:
        #         if i in neighbor_as:
        #             neighbor_as.remove(i)
        #     self.logger.debug(f"neighbor_as:{neighbor_as}")
        #     proto_name = link_meta["protocol_name"]
        #     ip_version = link_meta["remote_ip"].version
        #     
        #     if is_inter:
        #         self.logger.debug(self.bird_man.get_remote_fib())
        #         for p,data in self.bird_man.get_remote_fib().items():
        #             self.logger.debug(data["as_path"])
        #         data = get_bird_spd_data(proto_name, 
        #                              f"rpdp{ip_version}",
        #                              ip_version, 
        #                              sn,
        #                              self.config["router_id"],
        #                              [],
        #                              addresses,
        #                              is_inter,
        #                              self.config["local_as"],
        #                              link_meta["remote_as"],
        #                              )
        #     else:
        #         data = get_bird_spd_data(proto_name, 
        #                              f"rpdp{ip_version}",
        #                              ip_version, 
        #                              sn,
        #                              self.config["router_id"],
        #                              [],
        #                              addresses,
        #                              is_inter)
        #     self.logger.debug(data)
        #     timeout = 0
        #     msg = get_agent_bird_msg(
        #         data, "dsav", self.rpdp_app.name, timeout, False)
        #     # self.logger.debug(msg)
        #     self.link_man.put_send_async(msg)
        #     self.data["spd_sn"][proto_name] += 1

        return True

    def _interval_trigger(self):
        """
        run forever,
        trigger event here
        """
        check_interval = 1
        t0 = time.time()
        data = {
            "last_trigger": t0,
            "events": {
                "spd": {"last_trigger": t0, "interval": 5}
                # "spa_init": {"last_trigger": t0, "interval": 5}
            }
        }
        while True:
            # we check if spa init is sent on all links
            cur_t = time.time()
            if cur_t - data["last_trigger"] > check_interval:
                for event in data["events"]:
                    cur_t = time.time()
                    if cur_t - data["events"][event]["last_trigger"] > data["events"][event]["interval"]:
                        data["events"][event]["last_trigger"] = cur_t
                        if event == "spd":
                            self._refresh_kernel_fib()
                            # self.logger.debug("triggering spd")
                            if not self.data["metric"]["initial_fib_stable"]:
                                self.logger.debug(
                                    "fib not stable, not sending spd")
                                continue
                            self._send_spd()
                        else:
                            self.logger.warning(
                                f"unknown event:{event}, skipping")
            time.sleep(0.5)

    def _start(self):
        self._thread_pool = []
        self._thread_pool.append(threading.Thread(target=self._run))
        self._thread_pool.append(threading.Thread(target=self.link_man._run))
        self._thread_pool.append(threading.Thread(
            target=self._interval_trigger))
        for t in self._thread_pool:
            t.daemon = True
            t.start()

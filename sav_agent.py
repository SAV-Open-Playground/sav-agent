# -*-coding:utf-8 -*-
"""
@File    :   sav_agent.py
@Time    :   2023/01/10
@Author  :   Yuqian Shi
@Version :   0.1

@Desc    :   the sav_agent.py 
This is a benchmark to test the performance of BIRD
"""

import threading
from multiprocessing import Manager

import sys

from sav_common import *
from managers import *
from app_rpdp import RPDPApp
from app_urpf import UrpfApp
from app_efp_urpf import EfpUrpfApp
from app_fp_urpf import FpUrpfApp
from app_bar import BarApp
from app_passport import PassportApp


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
    def __init__(self, config, logger=None):
        if logger is None:
            logger = get_logger(__name__)
        self.send_buff = Manager().list()
        self.post_session = requests.Session()
        self.result_buff = {}
        self._job_id = 0
        self._add_lock = False
        self.update_config(config)

    def update_config(self, config):
        self.config = config

    def put_msg(self, msg):
        """
        supported type : ["http-post","grpc","quic"]
        timeout is in seconds, if set to 0, then will keep trying until sent
        "retry" is optional, if set, then will retry for that many times otehrwise will retry for 10 times  
        """
        while self._add_lock:
            pass
        self._add_lock = True
        key_types = [("type", str), ("data", dict),
                     ("timeout", int), ("store_rep", bool)]
        keys_types_check(msg, key_types)
        supported_type = ["http-post"]
        if not msg["type"] in supported_type:
            raise ValueError(
                f"unknown msg type {msg['type']} / {supported_type}")

        msg["pkt_id"] = self._job_id
        self.send_buff.append(msg)
        self._job_id += 1
        self._add_lock = False

    def send_msgs(self, msgs):
        for msg in msgs:
            match msg["type"]:
                case "http-post":
                    sent = self._send_http_post(msg)
                case _:
                    raise ValueError(f"unknown msg type {msg['type']}")
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

    def run(self):
        while True:
            temp = []
            while len(self.send_buff) > 0:
                temp.append(self.send_buff.pop(0))
            self.send_msgs(temp)


class SavAgent():
    def __init__(self, logger=None, path_to_config=os.path.join(
            os.path.dirname(os.path.abspath(__file__)), "SavAgent_config.json")):
        if logger is None:
            logger = get_logger("SavAgent")
        self.logger = logger
        self.config = {}
        self.link_man = None
        self.temp_for_link_man = []  # will be deleted after __init__
        self.path_to_config = path_to_config
        self.update_config(path_to_config)
        self._init_data()
        self.in_buff = Manager().list()
        self._init_apps()
        self.sib_man = SIBManager(logger=self.logger)
        self.ip_man = IPTableManager(self.logger, self.data["active_app"])
        self.sib_man.upsert("config", json.dumps(self.config))
        self.sib_man.upsert("active_app", json.dumps(self.data["active_app"]))
        self.bird_man = BirdCMDManager(logger=self.logger)
        self.bird_man.update_protocols(self.config["local_as"])
        self.sender = SendAgent(self.logger, self.config)
        self._start()
        # self.grpc_server = None

    def update_config(self, path_to_config):
        """
        return dictionary object if is a valid config file (only check type not value). 
        Otherwise, raise ValueError
        we should ALWAYS check self.config for latest values

        """
        for i in range(3):
            try:
                config = read_json(path_to_config)
                required_keys = [
                    ("apps", list), ("grpc_config", dict), ("location", str),
                    ("quic_config", dict), ("link_map", dict), ("rpdp_id", str), ("local_as", int)]
                keys_types_check(config, required_keys)

                grpc_config = config["grpc_config"]
                grpc_keys = [("server_addr", str), ("server_enabled", bool)]
                keys_types_check(grpc_config, grpc_keys)

                quic_config = config["quic_config"]
                grpc_keys = [("server_enabled", bool)]
                keys_types_check(quic_config, grpc_keys)
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
        # self.logger.debug(msg["sav_scope"])
        link = self.bird_man.get_link_meta_by_name(link["protocol_name"])
        self.rpdp_app.send_msg(msg, self.config, link)

    def _init_data(self):
        """
        all major data should be initialized here
        """
        self.data = {}
        self.data["metric"] = init_direction_metric()
        self.data["pkt_id"] = 0
        self.data["msg_count"] = 0
        self.data["links"] = {}  # link manager"s data
        self.data["fib"] = []  # system"s fib table
        # key is prefix (str), value is as paths in csv
        self.data["sav_table"] = {}
        # node key is as number, value is None; link key is as number,
        # value is list of directly connected as numbers, link is undirected
        self.data["sav_graph"] = {"nodes": {}, "links": {}}
        self.link_man = LinkManager(self.data["links"], logger=self.logger)
        for link_name, link_dict, link_type in self.temp_for_link_man:
            self.link_man.add(link_name, link_dict, link_type)
            self.temp_for_link_man = []
        self.data["apps"] = {}
        self.data["kernel_fib"] = {"data": parse_kernel_fib(),
                                   "update_time": time.time(),
                                   "check_time": time.time()}
        self.data["fib_for_apps"] = {}
        self.data["initial_bgp_stable"] = False

    def add_sav_nodes(self, nodes):
        data = self.data["sav_graph"]["nodes"]
        added = False
        for node in nodes:
            if not node in data:
                data[node] = None
                # self.logger.info(f"SAV GRAPH NODE ADDED :{node}")
                added = True
        if added:
            self.sib_man.upsert(
                "sav_graph", json.dumps((self.data["sav_graph"])))

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
            self.sib_man.upsert("sav_graph", json.dumps((data_dict)))
            self.logger.info(f"SAV GRAPH LINK ADDED :{key_asn}-{value_asn}")
            return
        # now key_asn in data_dict["links"]
        if value_asn not in data_dict["links"][key_asn]:
            data_dict["links"][key_asn].append(value_asn)
            self.sib_man.upsert("sav_graph", json.dumps((data_dict)))
            self.logger.info(f"SAV GRAPH LINK ADDED :{key_asn}-{value_asn}")

    def _init_apps(self):
        # bird and grpc are must
        self.rpdp_app = None
        self.passport_app = None
        self.data["active_app"] = None
        # self.logger.debug(self.config)
        if len(self.config["apps"]) == 0:
            self.logger.warning("no apps found, quiting")
            sys.exit(0)
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
                    self, self.config["local_as"], self.config["rpdp_id"], logger=self.logger)
                self.passport_app = app_instance
                self.add_app(app_instance)

            else:
                self.logger.error(msg=f"unknown app name: {name}")
            if self.config["enabled_sav_app"] == name:
                self.data["active_app"] = app_instance.name
        # if self.rpdp_app is None:
        #     msg = 'rpdp_app missing in config'
        #     self.logger.error(msg)
        #     raise ValueError(msg)
        self.logger.debug(
            msg=f"initialized apps: {list(self.data['apps'].keys())},using {self.data['active_app']}")

    def _update_kernel_fib(self):
        """return new_fib, adds, dels"""
        new_ = parse_kernel_fib()
        t0 = time.time()
        old_ = self.data["kernel_fib"]["data"]
        self.data["kernel_fib"]["check_time"] = t0
        adds = {}
        dels = {}
        for prefix in new_:
            if old_.get(prefix, None) != new_[prefix]:
                adds[prefix] = new_[prefix]
        for prefix in old_:
            if new_.get(prefix, None) != old_[prefix]:
                dels[prefix] = old_[prefix]
        if len(adds) + len(dels) > 0:
            self.data["kernel_fib"]["update_time"] = t0
            self.data["kernel_fib"]["data"] = new_
        return self.data["kernel_fib"]["data"], adds, dels

    def _if_bird_ready(self, stable_span=5):
        """
        check if the fib table is stabilized and if bird sent link meta to us
        """
        if self.data["initial_bgp_stable"]:
            return
        # self.logger.debug(self.bird_man.bird_fib)
        self._update_kernel_fib()
        if time.time() - self.data["kernel_fib"]["update_time"] > stable_span:

            self.logger.debug(
                f"FIB STABILIZED at {self.data['kernel_fib']['update_time']}")
            self.data["initial_bgp_stable"] = True
            if self.rpdp_app:
                self._notify_apps({}, {}, ["rpdp_app"])
            if self.passport_app:
                self._notify_apps({}, {}, ["passport_app"])
            # self.logger.info(
            # f"INITIAL PREFIX-AS_PATH TABLE {self.rpdp_app.get_pp_v4_dict()}")
            return
        # self.logger.debug("FIB NOT STABILIZED")

    def _run(self):
        """
        start a thread to check the cmd queue and process each cmd
        """
        while True:
            try:
                if self.data["initial_bgp_stable"]:
                    while len(self.in_buff) > 0:
                        try:
                            msg = self.in_buff.pop(0)
                            self.data["pkt_id"] += 1
                            msg["pkt_id"] = self.data["pkt_id"]
                            self._process_msg(msg)
                        except Exception as err:
                            self.logger.exception(err)
                            self.logger.error(
                                f"error when processing: [{err}]:{msg}")
                    self._send_init()
                    if self.rpdp_app:
                        while len(self.rpdp_app.prepared_cmd) > 0:
                            # may call_agent more than once
                            self.logger.debug("sending prepared cmd")
                            self.bird_man.bird_cmd("call_agent")

                else:
                    self._if_bird_ready(
                        stable_span=self.config.get("fib_stable_threshold"))
                    # TODO add initial notify_apps?
                    time.sleep(0.1)
            except Exception as e:
                self.logger.exception(e)
                self.logger.error(e)
                self.logger.error(type(e))

    def grpc_recv(self, msg, sender):
        self.logger.debug(f"agent recv via grpc: {msg} from {sender}")

    def _send_init(self):
        """
        decide whether to send initial broadcast of each link
        """
        rpdp_links = self.bird_man.get_all_rpdp_meta(self.config["link_map"])
        for link_name, link in rpdp_links.items():
            if link["initial_broadcast"]:
                continue
            if self._send_init_broadcast_on_link(
                    link, link_name):
                self.logger.info(
                    f"initial broadcast sent on {link_name} ")
                self.bird_man.update_link_meta(
                    link_name, "initial_broadcast", True)

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
        self.in_buff.append(msg)

    def _send_init_broadcast_on_link(self, link, link_name):
        # self.logger.debug(f"sending initial broadcast on link {link_name}")
        return self._send_origin(link_name, None)

    def _process_link_state_change(self, msg):
        """
        in this function, we manage the link state
        """
        if not msg["msg"]:
            return
        if self.passport_app:
            self.passport_app.init_key_publish()

    def _process_link_config(self, msg):
        """
        in this function, we add the config to corresponding link
        """

        msg["remote_as"] = int(msg["remote_as"])
        msg["local_as"] = int(msg["local_as"])
        if msg["remote_as"] == msg["local_as"]:
            msg["is_interior"] = False
        else:
            msg["is_interior"] = True
        if msg["as4_session"] == "True":
            msg["as4_session"] = True
        elif msg["as4_session"] == "False":
            msg["as4_session"] = False
        else:
            self.logger.error(
                f"unknown as4_session value {msg['as4_session']}")
        # the router_id we have is a int presentation of ipv4 address,
        # now convert it to standard ipv4 string
        # now we transform bird internal router id to ipv4
        msg["remote_id"] = str(hex(int(msg["router_id"])))[2:]
        while len(msg["remote_id"]) < 8:
            msg["remote_id"] = "0" + msg["remote_id"]
        temp = []
        while len(msg["remote_id"]) > 1:
            temp.append(str(int(msg["remote_id"][:2], 16)))
            msg["remote_id"] = msg["remote_id"][2:]
        msg["remote_id"] = ".".join(temp)
        if "rpdp" in msg["channels"]:
            msg["link_type"] = "modified_bgp"
        else:
            # self.logger.warning(msg)
            msg["link_type"] = "native_bgp"
        data_dict = get_new_link_meta("rpdp_app", msg["link_type"])
        for key in msg:
            if key in data_dict:
                data_dict[key] = msg[key]

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

    def _process_bgp_update(self, msg):
        """
        process bgp update message (from bird)
        """
        # self.logger.debug(f"{msg}")
        msg["msg"]["is_native_bgp"] = not (len(msg["msg"]["sav_nlri"]) > 0)
        if msg["msg"]["is_native_bgp"]:
            self._process_native_bgp_update()
        else:
            if self.rpdp_app:
                self.rpdp_app.recv_http_msg(msg)

    def _process_native_bgp_update(self, reset=False):
        """
        the msg is not used here
        """
        _, adds, dels = self._update_kernel_fib()
        if len(adds) == 0 and len(dels) == 0:
            return
        self.bird_man.update_fib(sib_man=self.sib_man)
        self._notify_apps(adds, dels, reset)
        self.logger.debug(f"_notify_apps finished")

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
                a, d = app.fib_changed(adds, dels)
            elif app_type in [EfpUrpfApp, FpUrpfApp, BarApp, PassportApp]:
                a, d = app.fib_changed()
            elif app_type in [RPDPApp]:
                adds, dels = self.rpdp_app.diff_pp_v4(reset)
                changed_routes = []
                for prefix, path in adds:
                    changed_routes.append({prefix: path})
                # self.logger.debug(f"changed_routes:{changed_routes}")
                self._send_origin(None, changed_routes)
            else:
                self.logger.error(f":{type(app)}")
            for rule in a:
                row = {"prefix":        rule[0],
                       "interface":     rule[1],
                       "source_app":    rule[2],
                       "neighbor_as":   rule[3]
                       }
                if rule[1] == "*":
                    up_link_names = self.bird_man.get_up_links().keys()
                    # TODO currently we only apply to bgp interfaces
                    for link_name in up_link_names:
                        link_dict = self.bird_man.get_link_meta_by_name(
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
        self.ip_man.add(add_rules)
        # self.update_sav_table(add_rules, del_rules)

    def update_sav_table(self, adds, dels):
        """
        update sav table, and notify apps
        """
        old_table = self.data["sav_table"]
        self.logger.debug(f"adds:{adds}")
        self.logger.debug(f"dels:{dels}")
        for r in adds:
            self.logger.debug(r)
        # self.logger.debug(f"adds:{adds}")
        # self.logger.debug(f"dels:{dels}")
        # for prefix in adds:
        #     if prefix not in self.data["sav_table"]:
        #         self.data["sav_table"][prefix] = []
        #     for path in adds[prefix]:
        #         add_path(path, self.data["sav_table"][prefix])
        # for prefix in dels:
        #     if prefix not in self.data["sav_table"]:
        #         self.logger.error(
        #             f"prefix {prefix} not in sav_table when deleting")
        #         continue
        #     for path in dels[prefix]:
        #         if path in self.data["sav_table"][prefix]:
        #             self.data["sav_table"][prefix].remove(path)
        #         else:
        #             self.logger.error(
        #                 f"path {path} not in sav_table when deleting")
        # self._update_sav_graph(adds, dels)
        # self._notify_apps(adds, dels, False)

    def _send_origin(self, input_link_name=None, input_paths=None):
        """
        send origin messages,
        if input_link_name is None, send to all available links
        if input_paths is None, send all local prefixes
        """
        # self.logger.debug(f"send_origin: {input_link_name} ,{input_paths}")
        if self.rpdp_app is None:
            self.logger.debug("rpdp_app missing,unable to send origin")
            return True
        t0 = time.time()
        inter_sent = False
        intra_sent = False
        try:
            link_names = [input_link_name]
            inter_links = []
            intra_links = []
            if input_link_name is None:
                # when sending origin, we send to all links
                # link_names = []
                # # self.logger.debug(self.link_man.data.keys())
                # for link_name, link_data in self.bird_man.get_all_link_meta().items():
                #     if self.config["link_map"].get(link_name):
                #         link_names.append(link_name)
                #     else:
                #         if link_data["status"]:
                #             link_names.append(link_name)
                up_links = self.bird_man.get_all_rpdp_meta(
                    self.config["link_map"])
                # self.logger.debug(f"up_links:{up_links}")
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
                for link_name in link_names:
                    meta = self.bird_man.get_link_meta_by_name(link_name)
                    if meta["is_interior"]:
                        inter_links.append((link_name, meta))
                    else:
                        intra_links.append((link_name, meta))
            # for link_name in link_names:
            #     link = self.link_man.data[link_name]
            #     mapped_type = self.config["link_map"].get(link_name)
            #     if link["link_type"] == "modified_bgp" or mapped_type:
            #         if link["is_interior"]:
            #             inter_links.append((link_name, link))
            #         else:
            #             intra_links.append((link_name, link))
            #     else:

            #         self.logger.error(
            #             f"sending origin on native-bgp link? {link_name}")
            # self.logger.debug(f"inter_links:{inter_links}")
            # self.logger.debug(f"intra_links:{intra_links}")
            inter_paths = []
            intra_paths = []
            if input_paths is None:

                ppv4 = self.bird_man.bird_fib["remote_route"]
                for prefix in ppv4:
                    for path in ppv4[prefix]["as_path"]:
                        inter_paths.append({prefix: path})
                    # prepare data for inter-msg TODO: intra-msg broadcast
            else:
                # self.logger.debug(input_paths)
                for path in input_paths:
                    for prefix in path:
                        path_data = list(map(str, path[prefix]))
                        # transfrom the data first
                        if tell_str_is_interior(",".join(path_data)):
                            # self.logger.debug(f"{path}")
                            inter_paths.append(path)
                        else:
                            intra_paths.append(path)
            # self.logger.debug(f"intra_paths:{intra_paths}")
            # self.logger.debug(f"inter_paths:{inter_paths}")
            inter_paths = aggregate_asn_path(inter_paths)
            # self.logger.debug(f"inter_paths:{inter_paths}")
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
                            inter_sent = True
                        else:
                            self.logger.debug(
                                f"no sav nlri, not sending inter origin")
            else:
                msg = f"no inter link:{len(inter_links)} or inter path:{len(inter_paths)}, not sending inter origin"
                # self.logger.debug(msg)
                return False
            if len(intra_links) > 0:
                for link in intra_links:
                    for remote_as, path in inter_paths.items():
                        msg = self.rpdp_app._construct_msg(
                            link, path, "origin", True)
                        # self.logger.debug(msg)
                        self.send_msg_to_agent(msg, link)
                        self.logger.debug(f"sent origin via intra{msg}")
                    # TODO intra origin
            t = time.time()-t0
            if t > TIMEIT_THRESHOLD:
                self.logger.debug(f"TIMEIT {time.time()-t0:.4f} seconds")
            return inter_sent
        except Exception as e:
            self.logger.exception(e)
            self.logger.error(e)
            return inter_sent

    def _process_msg(self, input_msg):
        t0 = time.time()
        log_msg = f"start msg, pkt_id:{input_msg['pkt_id']}, msg_type: {input_msg['msg_type']}"
        key_types = [("msg_type", str), ("pkt_id", int), ("pkt_rec_dt", float)]
        keys_types_check(input_msg, key_types)
        msg, m_t = input_msg["msg"], input_msg["msg_type"]
        # self.logger.debug(input_msg)
        match m_t:
            case "link_state_change":
                self._process_link_state_change(input_msg)
            case "bird_bgp_config":
                pass
            case "bgp_update":
                self._process_bgp_update(input_msg)
            case "native_bgp_update":
                self._process_native_bgp_update()
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
        if m_t in ["quic_msg", "passport_pkt", "grpc_msg", "bgp_update"]:
            if len(input_msg["msg"]["sav_nlri"]) > 0:
                self.data["msg_count"] += 1
                self.logger.debug(
                    f"PERF-TEST: got {m_t} packet ({self.data['msg_count']}) at {t0}")
                self.logger.debug(
                    f"PERF-TEST: finished PROCESSING ({self.data['msg_count']}) at {t1}")
        if t1-t0 > TIMEIT_THRESHOLD:
            log_msg = log_msg.replace("start", "finish")
            log_msg += f", time used: {t1-t0:.4f}"
            self.logger.debug(log_msg)
        metric = self.data["metric"]
        metric["count"] += 1
        metric["time"] += t1-t0
        metric["size"] += len(str(input_msg))

    def _start(self):
        self._thread_pool = []
        self._thread_pool.append(threading.Thread(target=self._run))
        self._thread_pool.append(threading.Thread(target=self.sender.run))
        for t in self._thread_pool:
            t.daemon = True
            t.start()

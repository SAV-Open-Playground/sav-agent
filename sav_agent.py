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
import subprocess
from multiprocessing import Manager
import copy
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
        self.msgs = Manager().list()
        self._init_apps()
        # we have self.data["active_app"] after self._init_apps()
        self.sib_man = SIBManager(logger=self.logger)
        self.ip_man = IPTableManager(self.logger, self.data["active_app"])
        self.sib_man.upsert("config", json.dumps(self.config))
        self.sib_man.upsert("active_app", json.dumps(self.data["active_app"]))
        self.bird_man = BirdCMDManager(logger=self.logger)
        self._start()
        # self.grpc_server = None

    def update_config(self, path_to_config):
        """
        return dictionary object if is a valid config file (only check type not value). 
        Otherwise, raise ValueError
        we should ALWAYS check self.config for latest values

        """
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
        except Exception as e:
            self.logger.debug(e)
            self.logger.exception(e)
            self.logger.error("invalid config file")

    def send_msg_to_agent(self, msg, link):
        """
        send message to another agent
        currently, only rpdp will sent to agent
        """
        # using grpc
        # self.logger.debug(msg["sav_scope"])
        link = self.link_man.data.get(link["protocol_name"])
        self.rpdp_app.send_msg(msg, self.config, link)

    def _init_data(self):
        """
        all major data should be initialized here
        """
        self.data = {}
        self.data["metric"] = init_metric()
        
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
        self.data["fib_for_stable"] = []
        self.data["fib_for_stable_read_time"] = time.time()
        self.data["fib_for_apps"] = []
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
            elif name == "BAR":
                app_instance = BarApp(self, logger=self.logger)
                self.add_app(app_instance)
            elif name == "passport":
                app_instance = PassportApp(self, self.config["local_as"],self.config["rpdp_id"],logger=self.logger)
                self.passport_app =app_instance
            else:
                self.logger.error(msg=f"unknown app name: {name}")
            if self.config["enabled_sav_app"] == name:
                self.data["active_app"] = app_instance.name
        if self.rpdp_app is None:
            msg = 'rpdp_app missing in config'
            self.logger.error(msg)
            raise ValueError(msg)
        self.logger.debug(
            msg=f"initialized apps: {list(self.data['apps'].keys())},using {self.data['active_app']}")

    def _if_bird_ready(self, stable_span=5):
        """
        check if the fib table is stabilized and if bird sent link meta to us
        """
        if self.data["initial_bgp_stable"]:
            return
        self._diff_fib("fib_for_stable")
        read_time = self.data.get("fib_for_stable_read_time", time.time())
        if time.time()-read_time > stable_span:
            self.logger.debug(f"FIB STABILIZED at {read_time}")
            self.data["initial_bgp_stable"] = True
            # self._diff_fib("fib")
            self._notify_apps(["rpdp_app"])
            self.logger.info(
                f"INITIAL PREFIX-AS_PATH TABLE {self.rpdp_app.get_pp_v4_dict()}")
            del self.data["fib_for_stable_read_time"]
            del self.data["fib_for_stable"]
            return
        # self.logger.debug("FIB NOT STABILIZED")

    def _run(self):
        """
        start a thread to check the cmd queue and process each cmd
        """
        while True:
            try:
                if self.data["initial_bgp_stable"]:
                    while len(self.msgs) > 0:
                        try:
                            msg = self.msgs.pop(0)
                            self.data["pkt_id"] += 1
                            msg["pkt_id"] = self.data["pkt_id"]
                            self._process_msg(msg)
                        except Exception as err:
                            self.logger.exception(err)
                            self.logger.error(
                                f"error when processing: [{err}]:{msg}")
                    self._send_link_init()
                    while len(self.rpdp_app.prepared_cmd) > 0:
                        # may call_agent more than once
                        self.logger.debug("sending prepared cmd")
                        self.bird_man.bird_cmd("call_agent")
                        # self.self.bird_man._bird_cmd("call_agent")

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

    def _send_link_init(self):
        """
        decide whether to send initial broadcast of each link
        """
        rpdp_links = self.link_man.rpdp_links(self.config["link_map"])
        # self.logger.debug(all_link_names)
        for link_name, link in rpdp_links:
            # self.logger.debug(json.dumps(link, indent=2))
            if link["initial_broadcast"] is False:
                # self.logger.debug(f"going to send to {link_name}")
                link["initial_broadcast"] = self._send_init_broadcast_on_link(
                    link, link_name)
        # self.logger.debug(f"finish {all_link_names}")

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
        return a list of local prefixes in nlri format
        """
        # update local fib table
        self._diff_fib("fib")
        prefixes = self.data.get("fib")
        # begin of filter
        temp = []
        for prefix in prefixes:
            temp.append(prefix)
        prefixes = temp
        # end of filter
        # get local prefix by gateway is 0.0.0.0
        prefixes = get_kv_match(prefixes, "Gateway", "0.0.0.0")
        # may have replicas, they have different metrics
        prefixes = list(
            set(map(lambda x: x["Destination"]+"/"+x["Genmask"], prefixes)))
        # self.logger.debug(f"local prefixes: {prefixes}")
        local_prefixes = list(map(netaddr.IPNetwork, prefixes))
        local_prefixes_for_upsert = json.dumps(list(map(str, local_prefixes)))
        self.sib_man.upsert("local_prefixes", local_prefixes_for_upsert)
        return local_prefixes

    def perf_test_send(self, ratio, nlri_num, total_pkt_num):
        raise NotImplementedError

    def get_fib(self):
        """
        parsing the output of "route -n -F" command
        """
        proc = subprocess.Popen(
            "route -n -F", shell=True, stdout=subprocess.PIPE)

        output = proc.stdout.read().decode()
        while "  " in output:
            output = output.replace("  ", " ")
        output = output.split("\n")
        output.pop()  # removing tailing empty line
        _ = output.pop(0)
        output = list(map(lambda x: x.split(" "), output))
        headings = output.pop(0)
        output = list(map(lambda x: dict(zip(headings, x)), output))
        # remove default route
        output = [i for i in output if i["Destination"] != "0.0.0.0"]
        self.sib_man.upsert("local_fib", json.dumps(output))
        # begin of filter

        return output

    def put_msg(self, msg):
        """
        should only be called via link
        """
        key_types = [("msg_type", str), ("source_app", str),
                     ("source_link", str),("pkt_rec_dt",float)]
        if not "msg" in msg:
            raise KeyError(f"msg missing in msg:{msg}")
        keys_types_check(msg, key_types)
        self.msgs.append(msg)

    def _send_init_broadcast_on_link(self, link, link_name):
        if not link["status"]:
            # self.logger.warning(f"{link_name} is down, not sending")
            return False
        self.logger.debug(f"sending initial broadcast on link {link_name}")
        return self._send_origin(link_name, None)

    def _process_link_state_change(self, msg):
        """
        in this function, we manage the link state
        """
        if not msg['source_link'].startswith("savbgp"):
            self.logger.debug(f"not sav link({msg['source_link']}), ignore")
            return
        meta = self.link_man.data.get(msg["source_link"])
        if meta:
            new_status = msg["msg"]
            if meta["status"] != new_status:
                meta["status"] = new_status
                self.link_man.update_link(meta)
                # self.logger.debug(f"{msg['source_link']} changed to {msg['msg']}")
            else:
                return  # no change
        else:
            link_dict = get_new_link_meta(
                msg["source_app"], msg["link_type"], msg["msg"])
            self.link_man.add(link_dict)
            self.logger.debug(f"{msg['source_link']} added {link_dict}")
        self.sib_man.upsert("link_data", json.dumps(self.link_man.data))
        self.logger.debug(
            f"link status changed: {msg['source_link']} now is {msg['msg']}")
        meta = self.link_man.data.get(msg["source_link"])
        if self.passport_app and msg["msg"]:
            self.passport_app.initialize_share_key(meta["remote_as"],meta["remote_ip"])
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
        # self.logger.debug(json.dumps(msg,indent=2))
        # self.logger.debug(json.dumps(data_dict,indent=2))
        if not self.link_man.exist(msg["protocol_name"]):
            self.link_man.add(data_dict)
        else:
            self.link_man.update_link(data_dict)
        self.sib_man.upsert("link_data", json.dumps(self.link_man.data))

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

    def _diff_fib(self, sub_type):
        """
        return list of added and deleted rows
        if for_stable is True, we use different "old fib"
        """
        if sub_type not in self.data:
            self.logger.error(f"unknown sub_type :{sub_type}")
        last_fib = self.data.get(sub_type)
        this_fib = self.get_fib()
        # self.logger.debug(f"last fib:{last_fib}, this_fib:{this_fib}")
        dels = []
        adds = []
        for row in this_fib:
            if not row in last_fib:
                adds.append(row)
        for row in last_fib:
            if not row in this_fib:
                dels.append(row)
        if len(adds + dels) > 0:
            self.data[sub_type] = this_fib
            self.data[f"{sub_type}_read_time"] = time.time()
        return adds, dels

    def _process_bgp_update(self, msg):
        """
        process  bgp update message (from bird)
        """
        self.logger.debug(f"{msg}")
        msg["msg"]["is_native_bgp"] = not (len(msg["msg"]["sav_nlri"]) > 0)
        if msg["msg"]["is_native_bgp"]:
            # self.data["msg_count"]+=1
            # self.logger.debug(f"PERF-TEST: got native BGP packet ({self.data['msg_count']}) at {time.time()}")
            # self.logger.debug(msg)
            self._process_native_bgp_update(msg)
            # self.logger.debug(f"PERF-TEST: finished PROCESSING ({self.data['msg_count']}) at {time.time()}")
        else:
            self.data["msg_count"] += 1
            self.logger.debug(
                f"PERF-TEST: got modified BGP packet ({self.data['msg_count']}) at {time.time()}")
            # self.logger.debug(msg)
            self.rpdp_app.recv_http_msg(msg)
            self.logger.debug(
                f"PERF-TEST: finished PROCESSING ({self.data['msg_count']}) at {time.time()}")

    def _process_native_bgp_update(self, msg, rest=False):
        """
        the msg is not used here
        """

        adds, dels = self.rpdp_app.diff_pp_v4(rest)
        if len(adds) == 0 and len(dels) == 0:
            return
        changed_routes = []
        # self.logger.debug(adds)
        for prefix, path in adds:
            changed_routes.append({prefix: path})
        self.logger.info(
            f"UPDATED LOCAL PREFIX-AS_PATH TABLE {self.rpdp_app.get_pp_v4_dict()}")
        self._send_origin(None, changed_routes)
        # self.logger.debug(f"_send_origin finished")
        self._notify_apps()
        self.logger.debug(f"_notify_apps finished")

    def reset(self):
        self._process_native_bgp_update(None, True)

    def _notify_apps(self, app_list=None):
        """
        rpdp logic is handled in other function
        here we pass the FIB change to SAV mechamthems,
        who does not need other information
        """
        adds, dels = self._diff_fib("fib_for_apps")
        add_rules = []
        del_rules = []
        if app_list is None:
            app_list = self.get_all_app_names()
        # self.logger.debug(f"notifying apps: {app_list}")
        # self.logger.debug(f"notifying apps: {self.data['apps'].keys()}")
        for app_name in app_list:
            app = self.get_app(app_name)
            self.logger.debug(f"calling app: {app_name}")
            a, d = [], []
            if isinstance(app, UrpfApp):
                a, d = app.fib_changed(adds, dels)
            elif (isinstance(app, EfpUrpfApp)
                  or isinstance(app, FpUrpfApp)
                  or isinstance(app, BarApp)):
                a, d = app.fib_changed()
            elif isinstance(app, RPDPApp):
                pass
            else:
                self.logger.error(f":{type(app)}")
            for rule in a:
                row = {"prefix": rule[0],
                       "interface": rule[1],
                       "source_app": rule[2],
                       "neighbor_as": rule[3]
                       }
                if rule[1] == "*":
                    up_link_names = self.link_man.get_all_up(True)
                    # TODO currently we only apply to bgp interfaces
                    for link_name in up_link_names:
                        link_dict = self.link_man.data.get(link_name)
                        row["local_role"] = link_dict["local_role"]
                        add_rules.append(row)
                else:
                    temp = self.link_man.get_bgp_by_interface(rule[1])
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
        for row in del_rules:
            self.logger.debug(f"TODO: deleting rule: {row}")
            pass  # TODO: delete

    def _send_origin(self, input_link_name=None, input_paths=None):
        """
        send origin messages,
        if input_link_name is None, send to all available links
        if input_paths is None, send all local prefixes
        """
        # self.logger.debug(f"send_origin: {input_link_name} ,{input_paths}")
        t0 = time.time()
        try:
            link_names = [input_link_name]
            inter_links = []
            intra_links = []
            if input_link_name is None:
                # when sending origin, we send to all links
                link_names = self.link_man.get_all_up()
                # self.logger.debug(link_names)
                # pre checking
                if len(link_names) == 0:
                    self.logger.debug("no link is up, not sending")
                    return False
            for link_name in link_names:
                link = self.link_man.data[link_name]
                mapped_type = self.config["link_map"].get(link_name)
                if link["link_type"] == "modified_bgp" or mapped_type:
                    if link["is_interior"]:
                        inter_links.append((link_name, link))
                    else:
                        intra_links.append((link_name, link))
                else:
                    
                    self.logger.error(
                        f"sending origin on native-bgp link? {link_name}")
            # self.logger.debug(f"inter_links:{inter_links}")
            # self.logger.debug(f"intra_links:{intra_links}")
            inter_paths = []
            intra_paths = []
            if input_paths is None:
                self.rpdp_app.diff_pp_v4()
                ppv4 = self.rpdp_app.get_pp_v4_dict()
                # self.logger.debug(ppv4)
                for prefix in ppv4:
                    for path in ppv4[prefix]["as_path"]:
                        inter_paths.append({prefix: path})
                    # prepare data for inter-msg TODO: intra-msg broadcast
            else:
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
                        self.logger.debug(f"inter_paths:{inter_paths}")
                        self.logger.debug(f"remote_as:{remote_as}")
                    else:
                        paths_for_as = inter_paths[remote_as]
                        # self.logger.debug(paths_for_as)
                        msg = self.rpdp_app._construct_msg(
                            link, paths_for_as, "origin", True)
                        self.logger.warning(f"sent origin via inter{msg}")
                        self.send_msg_to_agent(msg, link)
            else:
                self.logger.debug(
                    f"no inter link:{len(inter_links)} or inter path:{len(inter_paths)}, not sending inter origin")

            if len(intra_links) > 0:
                for link in intra_links:
                    for remote_as, path in inter_paths.items():
                        msg = self.rpdp_app._construct_msg(
                            link, path, "origin", True)
                        self.logger.debug(msg)
                        self.send_msg_to_agent(msg, link)
                        self.logger.debug(f"sent origin via intra{msg}")
                    # TODO intra origin
            t = time.time()-t0
            if t > TIMEIT_THRESHOLD:
                self.logger.debug(f"TIMEIT {time.time()-t0:.4f} seconds")
            return True
        except Exception as e:
            self.logger.exception(e)
            self.logger.error(e)
            return False

    def _process_msg(self, input_msg):
        t0 = time.time()
        log_msg = f"start msg, pkt_id:{input_msg['pkt_id']}, msg_type: {input_msg['msg_type']}"
        key_types = [("msg_type", str), ("pkt_id", int),("pkt_rec_dt",float)]
        keys_types_check(input_msg, key_types)
        msg, m_t = input_msg["msg"], input_msg["msg_type"]
        
        # self.logger.debug(input_msg)
        match m_t:
            case "link_state_change":
                self._process_link_state_change(input_msg)
            case "bird_bgp_config":
                self._process_link_config(msg)
            case "bgp_update":
                self._process_bgp_update(input_msg)
            case "native_bgp_update":
                self._process_native_bgp_update(input_msg)
            case "grpc_msg":
                # self.data["msg_count"]+=1
                self.rpdp_app.process_grpc_msg(input_msg)
            case "quic_msg":
                self.data["msg_count"] += 1
                self.logger.debug(
                    f"PERF-TEST: got quic packet ({self.data['msg_count']}) at {time.time()}")
                self.rpdp_app.process_quic_msg(input_msg)
                t1 = time.time()
                self.logger.debug(
                    f"PERF-TEST: finished PROCESSING ({self.data['msg_count']}) at {time.time()}")
            case "perf_test":
                self.rpdp_app.perf_test_send(list(map(json.loads,input_msg["msg"])))
            case _:
                self.logger.warning(f"unknown msg type: [{m_t}]\n{input_msg}")
            
        t1= time.time()-t0
        if t1 > TIMEIT_THRESHOLD:
            log_msg = log_msg.replace("start", "finish")
            log_msg += f", time used: {t1:.4f}"
            self.logger.debug(log_msg)
        metric = self.data["metric"]
        metric["count"] += 1
        metric["time"] += t1
        metric["size"] += len(str(input_msg))

    def _start(self):
        self._thread = threading.Thread(target=self._run)
        self._thread.daemon = True
        self._thread.start()

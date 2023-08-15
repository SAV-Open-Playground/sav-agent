# -*-coding:utf-8 -*-
"""
@File    :   sav_agent.py
@Time    :   2023/01/10
@Author  :   Yuqian Shi
@Version :   0.1

@Desc    :   the sav_agent.py is responsible for managing two types of critical instances : SavApp and SavLink.
They are responsible for message transmission and message preprocessing.
SavAgent also manages two types of critical data structure: SavGraph and SavTable.
SavGraph is built on the known AS_PATHs.
SAvTable is built on the sav messages.
"""

import threading
import subprocess
from multiprocessing import Manager
import copy
import sys

import grpc
import agent_msg_pb2
import agent_msg_pb2_grpc
from concurrent import futures

from sav_common import *
from managers import *
from app_rpdp import RPDPApp
from app_urpf import UrpfApp
from app_efp_urpf import EfpUrpfApp
from app_fp_urpf import FpUrpfApp
from app_bar import BarApp


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
        self.update_config(path_to_config)
        self._init_data()
        self.msgs = Manager().list()
        self._init_apps()
        # we have self.data["active_app"] after self._init_apps()
        self.sib_man = SIBManager(logger=self.logger)
        self.ip_man = IPTableManager(self.logger, self.data["active_app"])
        self.sib_man.upsert("config", json.dumps(self.config))
        self.sib_man.upsert("active_app", json.dumps(self.data["active_app"]))
        self._start()
        self.path_to_config = path_to_config
        # self.grpc_server = None

    def update_config(self, path_to_config):
        """
        return dictionary object if is a valid config file (only check type not value). 
        Otherwise, raise ValueError

        we should ALWAYS check self.config for latest values

        """
        try:
            config = read_json(path_to_config)
            required_keys = [("apps", list), ("grpc_config", dict), ("location", str)]
            keys_types_check(config, required_keys)

            grpc_config = config["grpc_config"]
            keys_types_check(grpc_config, [("enabled", bool)])
            if grpc_config["enabled"]:
                grpc_keys = [("server_addr", str), ("id", str), ("local_as", int),
                             ("enabled", bool), ("links", list)]
                keys_types_check(grpc_config, grpc_keys)
            if not self.link_man is None:
                for link_name in self.link_man.get_all_grpc():
                    self.link_man.delete(link_name)

            if grpc_config["enabled"]:
                src_id = grpc_config.get("id")
                local_as = grpc_config.get("local_as")
                # add grpc_links
                for grpc_link in grpc_config.get("links"):
                    dst = grpc_link["remote_addr"].split(':')
                    remote_as = grpc_link["remote_as"]
                    dst_ip = dst[0]
                    link_dict = get_new_link_dict("rpdp_app")
                    link_dict["meta"] = {
                        "local_ip": "unknown",
                        "remote_ip": dst_ip,
                        "dst_addr": grpc_link["remote_addr"],
                        "is_interior": local_as != remote_as,
                        "local_as": local_as,
                        "remote_as": remote_as,
                        "as4_session": True,  # True by default
                        "protocol_name": "grpc",
                        "local_role": grpc_link["local_role"],
                        "remote_id": grpc_link["remote_id"],
                        "interface_name": grpc_link["interface_name"],
                        "link_type": "grpc"
                    }

                    dst_id = grpc_link["remote_id"]
                    link_dict["status"] = True
                    if self.link_man is None:
                        self.temp_for_link_man.append(
                            (f"grpc_link_{src_id}_{dst_id}", link_dict, "grpc"))
                    else:
                        self.link_man.add(
                            f"grpc_link_{src_id}_{dst_id}", link_dict, "grpc")
                    self.logger.debug(
                        f"CONFIG UPDATE\n old:{self.config},\n new:{config}")
            self.config = config
        except Exception as e:
            self.logger.debug(e)
            self.logger.error("invalid config file")

    def _find_grpc_remote(self, remote_ip):
        for grpc_link in self.config["grpc_config"]["links"]:
            remote_addr = grpc_link["remote_addr"]
            if remote_addr.startswith(remote_ip):
                return (remote_addr, grpc_link["remote_id"])
        raise ValueError(f"remote_ip {remote_ip} not found in grpc_links")

    def _send_msg_to_agent(self, msg, link):
        """
        send message to another agent
        this function will decide to use grpc or reference router to send the message
        """
        if not isinstance(msg, dict):
            raise TypeError("msg must be a dict object")
        # using grpc
        # self.logger.debug(f"{link}")
        if link["link_type"] == "grpc":
            try:
                self.logger.debug(f"{msg['sav_nlri']}")
                if isinstance(msg["sav_nlri"][0], netaddr.IPNetwork):
                    msg["sav_nlri"] = list(map(prefix2str, msg["sav_nlri"]))

                remote_ip = link.get("meta").get("remote_ip")
                remote_addr, remote_id = self._find_grpc_remote(remote_ip)
                # self.logger.debug(f"sending to {remote_addr},{remote_id}")
                msg["dst_ip"] = remote_ip
                str_msg = json.dumps(msg)
                with grpc.insecure_channel(remote_addr) as channel:
                    stub = agent_msg_pb2_grpc.AgentLinkStub(channel)
                    # self.logger.debug(f"{self.config['grpc_config']['id']},{str_msg}")
                    agent_msg = agent_msg_pb2.AgentMsg(sender_id=self.config["grpc_config"]["id"],
                                                       json_str=str_msg)
                    rep = stub.Simple(agent_msg)
                    expected_str = f"got {str_msg}"
                    if not rep.json_str == expected_str:
                        raise ValueError(
                            f"expected {expected_str}, got {rep.json_str}")
                    if not rep.sender_id == remote_id:
                        self.logger.debug(
                            f"sending to {remote_addr},{remote_id}")
                        raise ValueError(
                            f"expected {remote_id}, got {rep.sender_id}")
            except Exception as e:
                self.logger.error(e)
        elif link["meta"]["link_type"] == "modified_bgp":
            # using reference router
            self.rpdp_app.send_msg(msg)

        elif link["meta"]["link_type"] == "native_bgp":
            # this should not happen
            self.logger.error(link)
            self.logger.error(msg)
        else:
            self.logger.error(f"unhandled msg {msg}")

    def _init_data(self):
        """
        all major data should be initialized here
        """
        self.data = {}
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
        self.data["fib_for_apps"] = []
        self.data["initial_bgp_stable"] = False

    def add_sav_link(self, asn_a, asn_b):
        data_dict = self.data["sav_graph"]
        if asn_a == asn_b:
            if not asn_a in data_dict["nodes"]:
                data_dict["nodes"][asn_a] = None
            self.sib_man.upsert("sav_graph", json.dumps((data_dict)))
            return
        self.logger.info(
            f"SAV GRAPH LINK  :{asn_a}-{asn_b}")
        # add node if not exist
        if not asn_a in data_dict["nodes"]:
            data_dict["nodes"][asn_a] = None
        if not asn_b in data_dict["nodes"]:
            data_dict["nodes"][asn_b] = None
        # add link if not exist
        key_asn = str(min(int(asn_a), int(asn_b)))
        value_asn = asn_a if key_asn == asn_b else asn_b
        if not key_asn in data_dict["links"]:
            data_dict["links"][key_asn] = [value_asn]
            self.sib_man.upsert("sav_graph", json.dumps((data_dict)))
            return
        elif value_asn not in data_dict["links"][key_asn]:
            data_dict["links"][key_asn].append(value_asn)
        self.sib_man.upsert("sav_graph", json.dumps((data_dict)))

    def _init_apps(self):
        # bird and grpc are must
        self.rpdp_app = None
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

    def _if_fib_stable(self, stable_span=5):
        """
        check if the fib table is stabilized
        """
        if self.data["initial_bgp_stable"]:
            return
        self._diff_fib("fib_for_stable")
        read_time = self.data.get("fib_for_stable_read_time", time.time())
        if time.time()-read_time > stable_span:
            self.logger.debug("FIB STABILIZED")
            self.data["initial_bgp_stable"] = True
            # self._notify_apps()
            self.logger.info(
                f"INITIAL PREFIX-AS_PATH TABLE {self.rpdp_app.get_pp_v4_dict()}")
            del self.data["fib_for_stable_read_time"]
            del self.data["fib_for_stable"]
            return

    def _run(self):
        """
        start a thread to check the cmd queue and process each cmd
        """
        while True:
            if self.data["initial_bgp_stable"]:
                if len(self.msgs) > 0:
                    try:
                        msg = self.msgs.pop(0)
                        self._process_msg(msg)
                    except Exception as err:
                        self.logger.error(
                            f"error when processing: [{err}]:{msg}")
                self._send_link_init()
            else:
                self._if_fib_stable(
                    stable_span=self.config.get("fib_stable_threshold"))
                # TODO add initial notify_apps?
                time.sleep(0.1)

    def grpc_recv(self, msg, sender):
        self.logger.debug(f"agent recv via grpc: {msg} from {sender}")

    def _send_link_init(self):
        """
        decide whether to send initial broadcast of each link
        """
        all_link_names = self.link_man.get_all_up()
        links_to_go = all_link_names
        for link_name in links_to_go:
            link = self.link_man.get(link_name)
            if len(link["meta"]) > 0:
                if link["initial_broadcast"] is False:
                    self._send_init_broadcast_on_link(link_name)
                    link["initial_broadcast"] = True

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
        # e.g. prefiex list [192.168.1.0/24, 192.168.0.0/16]
        # will be returned in "24,192,168,1,16,192,168"
        # update local fib table
        self._diff_fib("fib")
        prefixes = self.data.get("fib")
        # begin of filter
        temp = []
        for prefix in prefixes:
            if "192" in prefix["Destination"]:
                temp.append(prefix)
        prefixes = temp
        # end of filter
        # get local prefix by gateway is 0.0.0.0
        prefixes = get_kv_match(prefixes, "Gateway", "0.0.0.0")
        local_prefixes = list(map(lambda x: netaddr.IPNetwork(
            x["Destination"]+"/"+x["Genmask"]), prefixes))
        local_prefixes_for_upsert = json.dumps(list(map(str, local_prefixes)))
        self.sib_man.upsert("local_prefixes", local_prefixes_for_upsert)
        # self.logger.debug(local_prefixes)
        return local_prefixes

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
        self.sib_man.upsert("local_fib", json.dumps(output))
        # begin of filter

        return output

    def put_msg(self, msg):
        """
        should only be called via link
        """
        key_types = [("msg_type", str), ("source_app", str),
                     ("source_link", str)]
        if not "msg" in msg:
            raise KeyError(f"msg missing in msg:{msg}")
        keys_types_check(msg, key_types)
        self.msgs.append(msg)

    def _send_init_broadcast_on_link(self, link_name):
        link = self.link_man.get(link_name)
        if not link["status"]:
            self.logger.debug(f"link {link_name} is down, not sending")
            return
        self.logger.debug(f"sending initial broadcast on link {link_name}")
        self._send_origin(link_name, None)

    def _process_link_state_change(self, msg):
        """
        in this function, we manage the link state
        """
        # self.logger.debug(f"{msg}")
        if not msg['source_link'].startswith("savbgp"):
            self.logger.debug(f"not savgp link({msg['source_link']}), ignore")
            return
        link_name = msg["source_link"]
        link_dict = get_new_link_dict(msg["source_app"])
        link_dict["status"] = msg["msg"]
        if link_name in self.link_man.data:
            old_d = self.link_man.get(link_name)
            old_status = old_d["status"]
            new_status = link_dict["status"]
            if old_status != new_status:
                self.link_man.data[link_name]["status"] = link_dict["status"]
            else:
                return  # no change
        else:
            self.link_man.add(link_name, link_dict, msg["link_type"])
        self.logger.debug(f"link {link_name} is {link_dict['status']}")
        self.sib_man.upsert("link_data", json.dumps(self.link_man.data))

    def _process_link_config(self, msg):
        """
        in this function, we add the config to corresponding link
        """
        # self.logger.debug(msg)
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
        if not self.link_man.exist(msg["protocol_name"]):
            # self.logger.debug(msg)
            data_dict = get_new_link_dict(msg["protocol_name"])
            self.logger.debug(msg)
            data_dict["meta"] = msg
            # self.logger.debug(msg["protocol_name"])
            self.link_man.add(msg["protocol_name"],
                              data_dict, msg["link_type"])
        else:
            # self.logger.debug(msg["protocol_name"])
            self.link_man.add_meta(msg["protocol_name"], msg)
        self.sib_man.upsert("link_data", json.dumps(self.link_man.data))

    def _log_info_for_front(self, msg, log_type, link_name=None):
        """
        logging in specific format for front end
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
            # TODO: filter for demo
            if not row in last_fib:
                if "192" in row["Destination"]:
                    adds.append(row)
        for row in last_fib:
            if not row in this_fib:
                if "192" in row["Destination"]:
                    dels.append(row)

        if len(adds + dels) > 0:
            self.data[sub_type] = this_fib
            self.data[f"{sub_type}_read_time"] = time.time()
        return adds, dels

    def _process_bgp_update(self, msg):
        """
        process  bgp update message
        """
        # self.logger.debug(f"{msg}")
        if 'rpdp' in msg["msg"]["channels"]:
            self.rpdp_app.recv_http_msg(msg)
        else:
            self._process_native_bgp_update(msg)

    def _process_grpc_msg(self, msg):
        self.rpdp_app.process_grpc_msg(msg)

    def _process_native_bgp_update(self, msg):
        """
        the msg is not used here
        """

        adds, dels = self.rpdp_app.diff_pp_v4()
        if len(adds) == 0 and len(dels) == 0:
            return
        changed_routes = []
        self.logger.debug(adds)
        for prefix, path in adds:
            changed_routes.append({prefix: path})
        self.logger.info(
            f"UPDATED LOCAL PREFIX-AS_PATH TABLE {self.rpdp_app.get_pp_v4_dict()}")
        self._send_origin(None, changed_routes)
        self.logger.info(f"_send_origin finished")
        self._notify_apps()
        self.logger.info(f"_notify_apps finished")

    def _notify_apps(self):
        """
        rpdp logic is handled in other function
        here we pass the FIB change to SAV mechamthems,
        who does not need other information
        """
        adds, dels = self._diff_fib("fib_for_apps")
        add_rules = []
        del_rules = []
        for app_name in self.data['apps']:
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
                    temp = self.link_man.get_all_up_by_link_types(
                        ["native_bgp", "modified_bgp"])
                    # TODO currently we only apply to bgp interfaces
                    for link_dict in temp:
                        row["local_role"] = link_dict["meta"]["local_role"]
                        add_rules.append(row)
                else:
                    temp = self.link_man.get_bgp_by_interface(rule[1])
                    if len(temp) != 1:
                        self.logger.error(
                            f"multiple bgp on interface [{rule[1]}],{len(rule[1])}")
                    temp = temp[0]["meta"]
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
        link_names = [input_link_name]
        inter_links = []
        intra_links = []
        if input_link_name is None:
            # when sending origin, we send to all links
            link_names = self.link_man.get_all_up()
            # pre checking
            if len(link_names) == 0:
                self.logger.debug("no link is up, not sending")
                return
        for link_name in link_names:
            link = self.link_man.get(link_name)
            if link["link_type"] != "native_bgp":
                if link["meta"]["is_interior"]:
                    inter_links.append((link_name, link))
                else:
                    intra_links.append((link_name, link))
        inter_paths = []
        intra_paths = []
        if input_paths is None:
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
                remote_as = link["meta"]["remote_as"]
                if remote_as not in inter_paths:
                    # may happen when broadcasting, essentially is because the next as is not in the intended path
                    # TODO
                    self.logger.debug(f"inter_paths:{inter_paths}")
                    self.logger.debug(f"remote_as:{remote_as}")
                else:
                    paths_for_as = inter_paths[remote_as]
                    # self.logger.debug(paths_for_as)
                    msg = self.rpdp_app._construct_msg(
                        link, paths_for_as, "origin", True)
                    self._send_msg_to_agent(msg, link)
                    # self.get_app(link["app"]).send_msg(msg)
        else:
            self.logger.debug(
                f"no inter link:{len(inter_links)} or inter path:{len(inter_paths)}, not sending inter origin")

        if len(intra_links) > 0:
            for link in intra_links:
                for remote_as, path in inter_paths.items():
                    msg = self.rpdp_app._construct_msg(
                        link, path, "origin", True)
                    # self.logger.error(link)
                    self._send_msg_to_agent(msg, link)
                    # self.get_app(link["app"]).send_msg(msg)
                    self.logger.debug(f"sent origin via intra{msg}")
                  # TODO intra origin

    def _process_msg(self, input_msg):
        # self.logger.debug(f"processing msg: {input_msg['msg_type']}:{input_msg}")
        msg, m_t = input_msg["msg"], input_msg["msg_type"]
        if m_t == "link_state_change":
            self._process_link_state_change(input_msg)
        elif m_t == "bird_bgp_config":
            self._process_link_config(msg)
        elif m_t == "bgp_update":
            self._process_bgp_update(input_msg)
        elif m_t == "native_bgp_update":
            self._process_native_bgp_update(input_msg)
        elif m_t == "grpc_msg":
            self._process_grpc_msg(input_msg)

        else:
            self.logger.warning(f"unknown msg type: [{m_t}]\n{input_msg}")

    def _start(self):
        self._thread = threading.Thread(target=self._run)
        self._thread.daemon = True
        self._thread.start()

#!/usr/bin/python3
# -*- encoding: utf-8 -*-
"""
@Time    :   2023/01/10 08:04:55

SavAgent manages two types of critical instances : SavApp and SavLink.
They are responsible for message transmission and message preprocessing.
SavAgent also manages two types of critical data structure: SavGraph and SavTable.
SavGraph is built on the known AS_PATHs.
SAvTable is built on the sav messages.
"""
import threading
import subprocess
from multiprocessing import Manager
import copy

import grpc
import agent_msg_pb2
import agent_msg_pb2_grpc

from sav_common import *
from iptable_manager import IPTableManager, SIBManager
from app_rpdp import RPDPApp
from app_urpf import UrpfApp
from app_efp_urpf import EfpUrpfApp
from app_fp_urpf import FpUrpfApp


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
        if not logger:
            logger = get_logger("SavAgent")
        self.logger = logger
        self.config = self._config_validation(path_to_config)
        self._init_data()
        self.cmds = Manager().list()
        self._init_apps()
        # we have self.data["active_app"] after self._init_apps()
        self.sib_man = SIBManager(logger=self.logger)
        self.ip_man = IPTableManager(self.logger, self.data["active_app"])
        self.sib_man.upsert("config", json.dumps(self.config))
        self.sib_man.upsert("active_app", json.dumps(self.data["active_app"]))
        self._start()

    def _config_validation(self, path_to_config):
        """
        return dictionary object if is a valid config file. Otherwise, raise ValueError
        """
        config = read_json(path_to_config)
        required_keys = ["apps","grpc_links","grpc_id","grpc_server_addr"]
        for key in required_keys:
            if key not in config:
                self.logger.error(f"{key} is a must")
                raise ValueError("key missing in config")
    
        grpc_keys = ["remote_as","addr","remote_id"]
        for link in config["grpc_links"]:
            for key in grpc_keys:
                if key not in link:
                    self.logger.error(f"{key} is a must,{link}")
                    raise ValueError("key missing in config")

        return config

    def _find_grpc_remote(self, remote_ip):
        self.logger.debug(self.config["grpc_links"])
        for grpc_link in self.config["grpc_links"]:
            remote_addr = grpc_link["addr"]
            if remote_addr.startswith(remote_ip):
                return (remote_addr,grpc_link["remote_id"])
        raise ValueError(f"remote_ip {remote_ip} not found in grpc_links")

    def _send_msg_to_agent(self, msg, link):
        """
        send message to another agent
        this function will decide to use grpc or reference router to send the message
        """
        self.logger.debug(msg)
        if not isinstance(msg, dict):
            raise TypeError("msg must be a dict object")
        # using grpc
        if link["meta"]["link_type"]=="grpc":
            try:
                str_msg = json.dumps(msg)
                remote_ip = link.get("meta").get("remote_ip")
                remote_addr,remote_id = self._find_grpc_remote(remote_ip)
                with grpc.insecure_channel(remote_addr) as channel:
                    stub = agent_msg_pb2_grpc.AgentLinkStub(channel)
                    agent_msg = agent_msg_pb2.AgentMsg(sender_id=self.config.get("grpc_id"),
                                                       json_str=str_msg)
                    rep = stub.Simple(agent_msg)
                    expected_str = f"got {str_msg}"
                    if rep.json_str == expected_str and rep.sender_id == remote_id:
                        return
                    else:
                        self.logger.error(f"{rep}")
                        self.logger.error(f"expected sender:{remote_id}, got {rep.sender_id}")
                        self.logger.error(f"expected string:{expected_str}, got {rep.json_str}")
            except Exception as e:
                self.logger.error(e)
        elif link["meta"]["link_type"]=="modified_bgp":
        # using reference router
            self.get_app(link["app"]).send_msg(msg)
        elif link["meta"]["link_type"]=="native_bgp":
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
            f"SAV GRAPH LINK ADDED :{asn_a}-{asn_b}")
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
        # we enable grpc as default
        self.data["active_app"] = None
        
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
                app_instance = FpUrpfApp(
                    self, logger=self.logger)
                self.add_app(app_instance)
            elif name == "rpdp_app":
                self.rpdp_app = RPDPApp(self, logger=self.logger)
                self.add_app(self.rpdp_app)
            else:
                self.logger.error(msg=f"unknown app name: {name}")
            if self.data["active_app"] is None:
                self.data["active_app"] = app_instance.name
        if self.rpdp_app is None:
            msg = 'rpdp_app missing in config'
            self.logger.error(msg)
            raise ValueError(msg)
        self.logger.debug(
            msg=f"initialized optional apps: {list(self.data['apps'].keys())},using {self.data['active_app']}")

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
                if len(self.cmds) > 0:
                    try:
                        msg = self.cmds.pop(0)
                        self._process_msg(msg)
                    except Exception as err:
                        self.logger.error(
                            f"error when processing: [{err}]:{msg}")
                self._send_link_init()
            else:
                self._if_fib_stable(
                    stable_span=self.config.get("fib_stable_threshold"))
                time.sleep(0.1)

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
        local_prefixes_for_upsert = json.dumps(list(map(str,local_prefixes)))
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

    def put_msg(self, data):
        """
        should only be called via link
        """
        required_keys = ["msg", "msg_type", "source_app", "source_link"]
        for key in required_keys:
            if not key in data:
                raise KeyError(f"required key missing [{key}] in [{data}]")
        self.cmds.append(data)
        return

    def _send_init_broadcast_on_link(self, link_name):
        link = self.link_man.get(link_name)
        if not link["status"]:
            self.logger.debug(f"link {link_name} is down, not sending")
            return
        self.logger.debug(
            f"sending initial broadcast on link {link_name}")
        self._send_origin(link_name, None)

    def _get_new_link_dict(self, app_name):
        """
        generate a new link dict for adding
        """
        link_dict = {"status": False, "initial_broadcast": False,
                     "app": app_name, "meta": {}}
        return link_dict

    def _process_link_state_change(self, msg):
        """
        in this function, we manage the link state
        """
        man = self.link_man
        link_name = msg["source_link"]
        link_dict = self._get_new_link_dict(msg["source_app"])
        link_dict["status"] = msg["msg"]
        if link_name in man.data:
            old_d = man.get(link_name)
            old_status = old_d["status"]
            new_status = link_dict["status"]
            if old_status != new_status:
                man.data[link_name]["status"] = link_dict["status"]
        else:
            self.logger.debug(msg)
            # self.logger.debug(link_name)
            # self.logger.debug(link_dict)
            man.add(link_name, link_dict,msg["link_type"])
        self.sib_man.upsert("link_data", json.dumps(man.data))

    def _process_link_config(self, msg):
        """
        in this function, we add the config to corresponding link
        """
        # self.logger.debug(msg)
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
        msg["router_id"] = str(hex(int(msg["router_id"])))[2:]
        while len(msg["router_id"]) < 8:
            msg["router_id"] = "0" + msg["router_id"]
        temp = []
        while len(msg["router_id"]) > 1:
            temp.append(str(int(msg["router_id"][:2], 16)))
            msg["router_id"] = msg["router_id"][2:]
        msg["router_id"] = ".".join(temp)
        if "rpdp" in msg["channels"]:
            msg["link_type"] = "modified_bgp"
        else:
            # self.logger.warning(msg)
            msg["link_type"] = "native_bgp"
        if not self.link_man.exist(msg["protocol_name"]):
            self.logger.debug(msg)
            data_dict = self._get_new_link_dict(msg["protocol_name"])
            data_dict["meta"] = msg
            self.logger.debug(msg["protocol_name"])
            self.link_man.add(msg["protocol_name"], data_dict,msg["link_type"])
        else:
            self.logger.debug(msg["protocol_name"])
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

    def _process_sav_inter(self, msg, link):
        """
        determine whether to rela or terminate the message.
        """
        link_meta = link["meta"]
        scope_data = msg["sav_scope"]
        relay_msg = {
            "sav_nlri": msg["sav_nlri"],
            "sav_origin": msg["sav_origin"]
        }
        new_path = msg["sav_path"]+[link_meta["local_as"]]
        for i in range(len(new_path)-1):
            self.add_sav_link(new_path[i], new_path[i+1])
        self._log_info_for_front(msg=None, log_type="sav_graph")
        relay_scope = {}
        intra_links = self.link_man.get_all_up_type(is_interior=False)
        # if we receive a inter-domain msg via inter-domain link
        if link_meta["is_interior"]:
            for path in scope_data:
                next_as = path.pop(0)
                if (link_meta["local_as"] != next_as) :
                    path.append(next_as)
                    self.logger.error(
                        f"as number mismatch msg:{path} local_as {link_meta['local_as']}")
                    return
                if len(path) == 0:
                    self._log_info_for_front(msg, "terminate")

                    # AS_PATH:{msg['sav_path']} at AS {m['local_as']}")
                    for link_name in intra_links:
                        link = self.link_man.get(link_name)
                        relay_msg["sav_path"] = msg["sav_path"]
                        relay_msg["sav_scope"] = scope_data
                        relay_msg = self.rpdp_app._construct_msg(
                            link, relay_msg, "relay", True)
                        msg1 = relay_msg
                        msg1['sav_nlri'] = list(map(str, msg1['sav_nlri']))
                        self._log_info_for_front(
                            msg, "relay_terminate", link_name)
                        self.logger.debgug("")
                        self._send_msg_to_agent(msg, link)
                        # self.get_app(link["app"]).send_msg(relay_msg)
                else:
                    if path[0] in relay_scope:
                        # TODO here we may add incorrect AS(AS that we donnot have SAV link) 
                        relay_scope[path[0]].append(path)
                    else:
                        relay_scope[path[0]] = [path]
        # if we receive a inter-domain msg via intra-domain link
        else:
            self.logger.error("THIS SHOULD NOT HAPPEN ,no msg should be intra")
            if len(scope_data) > 0:
                # in demo we only rely this to inter-links
                for path in scope_data:
                    if path[0] in relay_scope:
                        relay_scope[path[0]].append(path)
                    else:
                        relay_scope[path[0]] = [path]
            else:
                # if receiving inter-domain msg via intra-domain link
                # and there is no scope data, it means we terminate the msg here
                return
        for next_as in relay_scope:
            inter_links = self.link_man.get_by(next_as, True)
            # native_ggp link may included
            inter_links = [i for i in inter_links if i["link_type"]!="native_bgp"]
            relay_msg["sav_scope"] = relay_scope[next_as]
            relay_msg["sav_path"] = msg["sav_path"] + [link_meta["local_as"]]
            for link in inter_links:
                relay_msg["sav_scope"] = relay_scope[next_as]
                relay_msg = self.rpdp_app._construct_msg(
                    link, relay_msg, "relay", True)
                self._send_msg_to_agent(relay_msg, link)
                # self.get_app(link["app"]).send_msg(relay_msg)
            if link_meta["is_interior"] and msg["is_interior"]:
                for link_name in intra_links:
                    link = self.link_man.get(link_name)
                    relay_msg = self._construct_msg(
                        link, relay_msg, "relay", True)
                    self._send_msg_to_agent(relay_msg, link)
                    # self.get_app(link["app"]).send_msg(relay_msg)
            if len(inter_links) == 0:
                if link_meta["is_interior"]:
                    self.logger.debug(
                        f"unable to find interior link for as:{next_as}, no SAV ?")

    def _process_sav_intra(self, msg, link_meta):
        """
        doing nothing but logging
        """
        self.logger.info(
            f"GOT INTRA-MSG ON [{link_meta['protocol_name']}]:{msg}, time_stamp: [{time.time()}]")
        if link_meta["is_interior"]:
            self.logger.error("intra-msg received on inter-link!")

    def _process_rpdp_msg(self, msg):
        """
        process sav message, only inter-domain is supported
        dpdp
        regarding the nlri part, the processing is the same
        """
        self.logger.debug(msg)
        this_link = self.link_man.get(msg["source_link"])
        link_meta = this_link["meta"]
        msg["src"] = link_meta["remote_ip"]
        msg["dst"] = link_meta["local_ip"]
        self._log_info_for_front(msg, "got_msg")
        # self.rpdp_app.preprocess_msg(msg)
        msg["is_interior"] = tell_str_is_interior(msg["sav_origin"])
        prefixes = msg["sav_nlri"]

        for prefix in prefixes:
            temp_dict = {"prefix": str(prefix),
                         "neighbor_as": link_meta["remote_as"],
                         "interface": msg["interface_name"],
                         "source_app": msg["app_name"],
                         "source_link": msg["source_link"]
                         }
            self.ip_man.add(temp_dict)
        if msg["is_interior"]:
            # in inter-domain, sav_path is as_path
            msg["sav_path"] = msg["as_path"]
            del msg["as_path"]
            self._process_sav_inter(msg, this_link)
        else:
            self.logger.error("INTRA MSG RECEIVED")
            self._process_sav_intra(msg, link_meta)

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
        process bgp update message, could be native bgp update message or sav message
        if native bgp update message, we use AS_PATH attribute to update the table of
        prefix to AS_PATH, this function relaying on RPDPApp
        """
        # if we receive a bgp update, indicating the link is up
        self.logger.debug(f"_process_bgp_update got:{msg}")
        link_name = msg["protocol_name"]
        self.link_man.get(key=link_name)["status"] = True
        if not msg["is_native_bgp"]:
            # this msg is for rpdp_app
            self._process_rpdp_msg(msg)
            return
        # send route changed info to apps
        # relying on bird app to get the as path of each prefix to send
        adds, dels = self.rpdp_app.diff_pp_v4()
        if len(adds) == 0 and len(dels) == 0:
            return
        changed_routes = []
        self.logger.debug(adds)
        for prefix, path in adds:
            changed_routes.append({prefix: path})
        # 
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
        self.logger.debug((adds, dels))
        add_rules = []
        del_rules = []
        for app_name in self.data['apps']:
            app = self.get_app(app_name)
            self.logger.debug(f"calling app: {app_name}")
            a, d = [], []
            if isinstance(app, UrpfApp):
                a, d = app.fib_changed(adds, dels)
            elif (isinstance(app, EfpUrpfApp) or isinstance(app, FpUrpfApp)):
                a, d = app.fib_changed()
            elif isinstance(app, RPDPApp):
                pass
            else:
                self.logger.error(f":{type(app)}")
            add_rules.extend(a)
            del_rules.extend(d)
        for row in add_rules:
            temp_dict = {"prefix": row[0],
                         "interface": row[1],
                         "source_app": row[2],
                         "neighbor_as": row[3]
                         }
            # self.logger.debug(temp_dict)
            self.ip_man.add(temp_dict)
        for row in del_rules:
            pass  # TODO: delete
            # self.ip_man.



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
                    inter_links.append(link)
                else:
                    intra_links.append(link)
        inter_paths = []
        intra_paths = []
        if input_paths is None:
            ppv4 = self.rpdp_app.get_pp_v4_dict()
            for prefix in ppv4:
                for path in ppv4[prefix]:
                    inter_paths.append({prefix: path})
                # prepare data for inter-msg TODO: intra-msg broadcast
        else:
            for path in input_paths:
                for prefix in path:
                    path_data = list(map(str, path[prefix]))
                    # transfrom the data first
                    if tell_str_is_interior(",".join(path_data)):
                        inter_paths.append(path)
                    else:
                        intra_paths.append(path)
        # self.logger.debug(intra_paths)
        # self.logger.debug(inter_paths)
        inter_paths = aggregate_asn_path(inter_paths)
        if len(inter_links) > 0 and len(inter_paths) > 0:
            # we send origin to all links no matter inter or intra
            for link in inter_links:
                # generate msg for this link
                remote_as = int(link["meta"]["remote_as"])
                if not link["initial_broadcast"]:
                    self._send_init_broadcast_on_link(link_name)
                if remote_as not in inter_paths:
                    # may happen when broadcasting
                    pass
                else:
                    paths_for_as = inter_paths[remote_as]
                    # self.logger.debug(paths_for_as)
                    msg = self.rpdp_app._construct_msg(
                        link, paths_for_as, "origin", True)
                    # self.logger.error(link)
                    self.logger.debug(msg)
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
        self.logger.debug(f"processing msg: {input_msg['msg_type']}:{input_msg}")
        msg, m_t = input_msg["msg"], input_msg["msg_type"]
        if m_t == "link_state_change":
            self._process_link_state_change(input_msg)
        elif m_t == "bird_bgp_config":
            self._process_link_config(msg)
        elif m_t == "bgp_update":
            msg["source_link"] = msg["protocol_name"]
            msg["app_name"] = input_msg["source_app"]
            self._process_bgp_update(msg)
        else:
            self.logger.warning(f"unknown msg type: [{m_t}]\n{input_msg}")

    def _start(self):
        self._thread = threading.Thread(target=self._run)
        self._thread.daemon = True
        self._thread.start()
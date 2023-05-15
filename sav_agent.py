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

from sav_common import *
from iptable_manager import IPTableManager, SIBManager
from bird_app import BirdApp
from urpf_app import UrpfApp
from efp_urpf_app import EfpUrpfApp
from fp_urpf_app import FpUrpfApp


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
        self.sib_man.upsert("config", str(self.config))
        self.sib_man.upsert("active_app", str(self.data["active_app"]))
        self._start()

    def _config_validation(self, path_to_config):
        """
        return dictionary object if is a valid config file. Otherwise, raise ValueError
        """
        config = read_json(path_to_config)
        if "bird" not in config["required_apps"]:
            raise ValueError("bird is a must")
        return config

    def _init_data(self):
        """
        all major data should be initialized here
        """
        self.data = {}
        self.data["links"] = {}  # link manager"s data
        # bird_app is a must
        self.data["required_apps"] = self.config["required_apps"]
        self.data["fib"] = []  # system"s fib table
        # key is prefix (str), value is as paths in csv
        self.data["sav_table"] = {}
        # node key is as number, value is None; link key is as number,
        # value is list of directly connected as numbers, link is undirected
        self.data["sav_graph"] = {"nodes": {}, "links": {}}
        self.link_man = LinkManager(self.data["links"], logger=self.logger)
        self.data["apps"] = {}
        self.data["fib_for_stable"] = []
        self.data["initial_bgp_stable"] = False

    def add_sav_link(self, asn_a, asn_b):
        data_dict = self.data["sav_graph"]
        if asn_a == asn_b:
            if not asn_a in data_dict["nodes"]:
                data_dict["nodes"][asn_a] = None
            self.sib_man.upsert("sav_graph", str(data_dict))
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
            self.sib_man.upsert("sav_graph", str(data_dict))
            return
        elif value_asn not in data_dict["links"][key_asn]:
            data_dict["links"][key_asn].append(value_asn)
        self.sib_man.upsert("sav_graph", str(data_dict))

    def log_local_asn_table(self):
        self.logger.info(
            f"UPDATED LOCAL PREFIX-AS_PATH TABLE {self.bird_app.get_pp_v4_dict()}")

    def _init_apps(self):
        for name in self.data["required_apps"]:
            if name == "bird":
                app_instance = BirdApp(self, logger=self.logger)
                self.add_app(app_instance)
                self.bird_app = app_instance
            elif name == "strict-uRPF":
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
            else:
                self.logger.error(msg=f"unknown app name: {name}")
        self.data["active_app"] = self.data["required_apps"][0]

        self.logger.debug(
            msg=f"initialized apps: {self.data['required_apps']},using {self.data['active_app']}")

    def _if_fib_stable(self, stable_span=5):
        """
        check if the fib table is stabilized
        """
        if self.data["initial_bgp_stable"]:
            return
        self._diff_fib(for_stable=True)
        read_time = self.data.get("fib_for_stable_read_time", time.time())
        if time.time()-read_time > stable_span:
            self.logger.debug("FIB STABILIZED")
            self.data["initial_bgp_stable"] = True
            self.logger.info(
                f"INITIAL PREFIX-AS_PATH TABLE {self.bird_app.get_pp_v4_dict()}")
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
                            f"error when processing: {err}:{msg}")
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
        for link_name in all_link_names:
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
        # self._diff_fib()
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
        self.sib_man.upsert("local_prefixes", str(local_prefixes))
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
        self.sib_man.upsert("local_fib", str(output))
        # begin of filter

        return output

    def put_msg(self, data):
        """
        should only be called via link
        """
        required_keys = ["msg", "msg_type", "source_app", "source_link"]
        for key in required_keys:
            if not key in data:
                raise KeyError(f"required key missing {key} {data}")
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
        and decide whether to broadcast
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
            man.add(link_name, link_dict)
        self.sib_man.upsert("link_data", str(man.data))

    def _process_link_config(self, msg):
        """
        in this function, we add the config to corresponding link
        """
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
        if not self.link_man.exist(msg["protocol_name"]):
            data_dict = self._get_new_link_dict(msg["protocol_name"])
            data_dict["meta"] = msg
            self.link_man.add(msg["protocol_name"], data_dict)
        else:
            self.link_man.add_meta(msg["protocol_name"], msg)
        self.sib_man.upsert("link_data", str(self.link_man.data))

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

    def _process_sav_inter(self, msg, link_meta):
        """
        determine whether to rela or terminate the message.
        """
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
                # if receiving inter-domain msg via inter-domain link ,we check
                if link_meta["local_as"] != next_as:
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
                        relay_msg = self._construct_msg(
                            link, relay_msg, "relay", True)
                        msg1 = relay_msg
                        msg1['sav_nlri'] = list(map(str, msg1['sav_nlri']))
                        self._log_info_for_front(
                            msg, "relay_terminate", link_name)

                        self.get_app(
                            name=link["app"]).send_msg(relay_msg)
                else:
                    if path[0] in relay_scope:
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
            relay_msg["sav_scope"] = relay_scope[next_as]
            relay_msg["sav_path"] = msg["sav_path"] + [link_meta["local_as"]]
            for link in inter_links:
                relay_msg["sav_scope"] = relay_scope[next_as]
                relay_msg = self._construct_msg(
                    link, relay_msg, "relay", True)
                self.get_app(link["app"]).send_msg(relay_msg)
            if link_meta["is_interior"] and msg["is_interior"]:
                for link_name in intra_links:
                    link = self.link_man.get(link_name)
                    relay_msg = self._construct_msg(
                        link, relay_msg, "relay", True)
                    self.get_app(link["app"]).send_msg(relay_msg)
            if len(inter_links) == 0:
                if link_meta["is_interior"]:
                    self.logger.error(
                        f"unable to find interior link for as:{next_as}")

    def _process_sav_intra(self, msg, link_meta):
        """
        doing nothing but logging
        """
        self.logger.info(
            f"GOT INTRA-MSG ON [{link_meta['protocol_name']}]:{msg}, time_stamp: [{time.time()}]")
        if link_meta["is_interior"]:
            self.logger.error("intra-msg received on inter-link!")

    def _process_sav_msg(self, msg):
        """
        process sav message, only inter-domain is supported
        """
        # regarding the nlri part, the processing is the same
        this_link = self.link_man.get(msg["source_link"])
        link_meta = this_link["meta"]
        msg["src"] = link_meta["remote_ip"]
        msg["dst"] = link_meta["local_ip"]
        self._log_info_for_front(msg, "got_msg")
        # self.logger.debug(link_meta)
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
            self._process_sav_inter(msg, link_meta)
        else:
            self.logger.error("INTRA MSG RECEIVED")
            self._process_sav_intra(msg, link_meta)

    def _diff_fib(self, for_stable=False):
        """
        return list of added and deleted rows
        if for_stable is True, we use different "old fib"
        """
        if for_stable:
            last_fib = self.data.get("fib_for_stable")
        else:
            last_fib = self.data.get("fib")

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
            if for_stable:
                self.data["fib_for_stable"] = this_fib
                self.data["fib_for_stable_read_time"] = time.time()
            else:
                self.data["fib"] = this_fib
        return adds, dels

    def _process_bgp_update(self, msg):
        """
        process bgp update message, could be native bgp update message or sav message
        if native bgp update message, we use AS_PATH attribute to update the table of
        prefix to AS_PATH, this function relaying on birdapp
        """
        # if we receive a bgp update, indicating the link is up
        link_name = msg["protocol_name"]
        self.link_man.get(key=link_name)["status"] = True
        if not msg["is_native_bgp"]:
            self._process_sav_msg(msg)
            return
        # send route changed info to apps
        # relying on bird app to get the as path of each prefix to send
        adds, dels = self.bird_app.diff_pp_v4()

        # the results are filtered for demo in Birdapp
        if len(adds) == 0 and len(dels) == 0:
            return
        changed_routes = []
        for prefix, path in adds:
            changed_routes.append({prefix: path})
        # self.logger.debug(changed_routes)
        # in this Demo no remove is required
        self.log_local_asn_table()
        self._send_origin(None, changed_routes)
        self._notify_apps()

    def _notify_apps(self):
        """
        only notify apps that has no links 
        """
        adds, dels = self._diff_fib()
        add_rules = []
        del_rules = []
        for app_name in self.data['apps']:
            app = self.get_app(app_name)
            self.logger.debug(f"calling app :{app_name}")
            a, d = [], []
            if isinstance(app, UrpfApp):
                a, d = app.fib_changed(adds, dels)
            elif isinstance(app, EfpUrpfApp):
                a, d = app.fib_changed()
            elif isinstance(app, FpUrpfApp):
                a, d = app.fib_changed()
            elif isinstance(app, BirdApp):
                pass
            else:
                self.logger.error(f":{type(app)}")
            add_rules.extend(a)
            del_rules.extend(d)
        for row in add_rules:
            temp_dict = {"prefix": row[0],
                         "neighbor_as": row[3],
                         "interface": row[1],
                         "source_app": row[2]
                         }
            # self.logger.debug(temp_dict)
            self.ip_man.add(temp_dict)
        for row in del_rules:
            pass  # TODO: delete
            # self.ip_man.

    def _construct_msg(self, link, input_msg, msg_type, is_inter):
        """
        construct a message for apps to use,
        if msg_type is origin, input_msg is the value of sav_scope list of paths
        if msg_type is relay, input_msg a dict include sav_path, sav_nlri, sav_origin, sav_scope
        """
        msg = {
            "src": link["meta"]["local_ip"],
            "dst": link["meta"]["remote_ip"],
            "msg_type": msg_type,
            "is_interior": is_inter,
            "as4_session": link["meta"]["as4_session"],
            "protocol_name": link["meta"]["protocol_name"],
        }
        if msg_type == "origin":
            if is_inter:
                msg["sav_origin"] = link["meta"]["local_as"]
                msg["sav_scope"] = input_msg
            else:
                msg["sav_origin"] = link["meta"]["router_id"]
            msg["sav_path"] = [msg["sav_origin"]]
            msg["sav_nlri"] = self.get_local_prefixes()

        elif msg_type == "relay":
            msg["sav_origin"] = input_msg["sav_origin"]
            msg["sav_nlri"] = input_msg["sav_nlri"]
            msg["sav_path"] = input_msg["sav_path"]
            msg["sav_scope"] = input_msg["sav_scope"]

        else:
            self.logger.error(f"unknown msg_type:{msg_type}\nmsg:{msg}")
        # self.logger.debug(msg["msg_type"])
        # self.logger.debug(msg["sav_scope"])
        # filter out empty sav_scope
        temp = []
        for path in msg["sav_scope"]:
            if len(path) > 0:
                temp.append(path)
        msg["sav_scope"] = temp
        return msg

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
            if link["meta"]["is_interior"]:
                inter_links.append(link)
            else:
                intra_links.append(link)
        inter_paths = []
        intra_paths = []
        if input_paths is None:
            ppv4 = self.bird_app.get_pp_v4_dict()
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
                    msg = self._construct_msg(
                        link, paths_for_as, "origin", True)
                    self.get_app(link["app"]).send_msg(msg)
        else:
            self.logger.debug(
                "no inter link or inter path, not sending inter origin")

        if len(intra_links) > 0:
            for link in intra_links:
                for remote_as, path in inter_paths.items():
                    msg = self._construct_msg(
                        link, path, "origin", True)
                    self.get_app(link["app"]).send_msg(msg)
                    self.logger.debug(f"sent origin via intra{msg}")
                  # TODO intra origin

    def _process_msg(self, input_msg):
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

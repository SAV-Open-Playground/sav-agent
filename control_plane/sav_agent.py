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
from sav_app import *
from data_plane.data_plane_enable import interceptor
from pyroute2 import IPRoute, IPDB


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


def add_prefix(prefixes, interface="savop_dummy") -> None:

    run_cmd(f"ip link add {interface} type dummy")
    run_cmd(f"ip link set {interface} up")
    for p in prefixes:
        ip = p[0]
        run_cmd(f"ip addr add {ip} dev {interface}")
class SendAgent():
    def __init__(self, agent, config, logger) -> None:
        """
        currently we don't handle the reply (ignore), don't use if you need reply
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

        # self.sib_man = s(logger=self.logger)
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
        for i in range(3):
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
                if config["use_ignore_nets"]:
                    self.ignore_prefixes = list(
                        set(map(netaddr.IPNetwork, self.config["ignore_nets"])))
                else:
                    self.ignore_prefixes = []
                if not config["enabled_sav_app"] in config["apps"]:
                    raise ValueError(
                        f"enabled_sav_app {config['enabled_sav_app']} not in apps:{config['apps']}")
                # add ips to dummy interface
                # self.logger.debug(config["prefix_method"])
                # if config["prefix_method"] == "independent_interface":
                #     add_prefix(config["prefixes"].keys())
                #     self.logger.debug(f"added prefix to dummy interface")
                return
            except Exception as e:
                self.logger.exception(e)
                self.logger.error(f"invalid config file ,retry {i+1}")
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

    def _init_sav_table(self) -> None:
        self.data["sav_table"] = {}

    def _init_data(self, first_dt) -> None:
        """
        all major data should be initialized here
        """
        self.default_rules = []
        self.data = {
            "pkt_id": 0,
            "msg_count": 0,
            "active_app": None,
            "fib_for_apps": {},
            "apps": {},
            "aspa_info": {},  # roa is stored in bird_man
            "roa_info": {},
            "links": {},  # link manager"s data
            "fib": [],  # system"s fib table
            "adj_in": {}  # bird"s adj-in table
        }
        self.data["metric"] = init_protocol_metric()
        self.data["metric"]["first_dt"] = first_dt
        self.data["metric"]["initial_fib_stable"] = False
        self.data["metric"]["is_fib_stable"] = False
        self.data["metric"]["skipped_bgp_update"] = 0
        # key is prefix (str), value is as paths in csv
        self._init_sav_table()
        # node key is as number, value is None; link key is as number,
        # value is list of directly connected as numbers, link is undirected
        self.data["sav_graph"] = {"nodes": {}, "links": {}}
        self.link_man = LinkManager(
            self.data["links"], self, logger=self.logger)
        self.data["kernel_fib"] = {"data": parse_kernel_fib(),
                                   "update_time": time.time(),
                                   "check_time": time.time()}
        self.rpdp_app = None
        self.passport_app = None

    def add_sav_nodes(self, nodes):
        data = self.data["sav_graph"]["nodes"]
        added = False
        for node in nodes:
            if not node in data:
                data[node] = None
                # self.logger.info(f"SAV GRAPH NODE ADDED :{node}")
                added = True
        if added:
            pass

    def add_sav_link(self, asn_a, asn_b) -> None:
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
            self.logger.info(f"SAV GRAPH LINK ADDED :{key_asn}-{value_asn}")
            return
        # now key_asn in data_dict["links"]
        if value_asn not in data_dict["links"][key_asn]:
            data_dict["links"][key_asn].append(value_asn)
            self.logger.info(f"SAV GRAPH LINK ADDED :{key_asn}-{value_asn}")

    def _init_apps(self) -> None:
        """
        init all app instances
        """
        # bird and grpc are must
        # self.logger.debug(self.config["apps"])
        if len(self.config["apps"]) == 0:
            self.logger.warning("no sav app given")
        all_instances = sav_app_init(self, self.logger)
        # self.logger.debug(all_instances)
        sav_apps = {}
        for app_id in self.config["apps"]:
            self.logger.debug(f"app_id:{app_id}")
            if not app_id in all_instances:
                self.logger.error(f"app_id:[{app_id}] not recognized")
                continue
            sav_apps[app_id] = all_instances[app_id]
            if app_id == RPDP_ID:
                self.rpdp_app = sav_apps[app_id]
            if app_id == PASSPORT_ID:
                self.passport_app = sav_apps[app_id]
        self.data["apps"] = sav_apps
        self.data["active_app"] = self.data["apps"][self.config["enabled_sav_app"]]
        self.logger.debug(
            msg=f"initialized apps: {list(self.data['apps'].keys())},using {self.data['active_app'].app_id}")

    def get_aspa_info(self):
        """
        TODO: when to refresh aspa_info,
        in our current design, we only refresh aspa_info once is enough
        """
        if self.data["aspa_info"] == {}:
            self._refresh_aspa_info()
        return copy.deepcopy(self.data["aspa_info"])

    def _get_rpki_info(self, uri):
        host = "savopkrill.com"
        port = 3000
        pwd = "krill"
        url = f"https://{host}:{port}/api/v1/cas/testbed/{uri}"
        headers = {"Authorization": f"Bearer {pwd}",
                   "Content-Type": "application/json"}
        while True:
            try:
                response = requests.request(
                    "GET", url, headers=headers, verify=False, timeout=15)
                response.raise_for_status()  # Raises an exception for any HTTP error status codes
                ret = response.json()
                return ret
            except Exception as err:
                self.logger.debug(err)
                self.logger.error(f"get {url} failed")
                time.sleep(0.1)

    def _refresh_aspa_info(self) -> None:
        """
        update aspa_info: {customer_asn:[provider_asn]}
        """
        ret_json = self._get_rpki_info("aspas")
        ret = {}
        for item in ret_json:
            customer_asn = item["customer"]
            provider_asns = item["providers"]
            ret[customer_asn] = list(
                map(lambda x: int(x.replace("AS", "").replace("(v4)", "")), provider_asns))
        self.data["aspa_info"] = ret

    def _refresh_roa_info(self, hostname="savopkrill.com", port_number=3000, pwd="krill"):
        ret = self._get_rpki_info("routes")
        for r in ret:
            if not r["asn"] in self.data["roa_info"]:
                self.data["roa_info"][r["asn"]] = []
            p = netaddr.IPNetwork(r["prefix"])
            self.data["roa_info"][r["asn"]].append(p)

    def get_roa_info(self):
        """
        return a dict,key is customer_asn,value is list of providers
        """
        return copy.deepcopy(self.data["roa_info"])

    def _get_route_pyroute(self, route, ifas):
        dst = route.get_attr('RTA_DST')
        oif = route.get_attr('RTA_OIF')
        gateway = route.get_attr('RTA_GATEWAY')
        if dst is None:
            raise ValueError("dst is None")
        p = f"{dst}/{route.get('dst_len')}"
        p = netaddr.IPNetwork(p)
        ret = {"Destination": f"{p.ip}",
               "Genmask": f"{p.netmask}",
               "Gateway": gateway,
               'Metric': route.get_attr("RTA_PRIORITY"),
               }
        if oif is None:
            ret["Iface"] = None
        else:
            ret["Iface"] = f"{ifas[oif].ifname}"
        return p, ret

    def parse_kernel_fib3(self) -> dict:
        try:
            routes = IPRoute().get_routes()
            ifas = IPDB().interfaces
            ret = {}
            for route in routes:
                # self.logger.debug(route)
                # self.logger.debug(type(route))
                # self.logger.debug(dir(route))
                if route.get_attr('RTA_DST') is None:
                    # or route.get_attr('RTA_GATEWAY') is None:
                    continue
                k, v = self._get_route_pyroute(route, ifas)
                if k == netaddr.IPNetwork("0.0.0.0/0") or k == netaddr.IPNetwork("::/0"):
                    continue
                ret[k] = v

            return ret
        except Exception as e:
            self.logger.exception(e)
            self.logger.error(e)
            return {}
    def _refresh_kernel_fib(self, filter_base=True):
        """
        update kernel fib using cmd
        tell if kernel fib has changed
        return adds, dels
        """
        # new_ = self.parse_kernel_fib3()
        new_ = parse_kernel_fib()
        # for k in ["127.0.0.0/8", "127.0.0.1/32", "127.255.255.255/32"]:
        #     if netaddr.IPNetwork(k) in new_:
        #         del new_[netaddr.IPNetwork(k)]
        # for k, v in new_.items():
        #     self.logger.warn(f"{k}:{v}")
        # for k, v in self.parse_kernel_fib3().items():
        #     self.logger.warn(f"{k}:{v}")
        #
        if filter_base:
            remove_prefixes = self.ignore_prefixes
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
        old_ = self._get_kernel_fib()
        # self.logger.debug(old_)
        self.data["kernel_fib"]["check_time"] = t0
        adds = {}
        dels = {}
        for prefix in new_:
            if "Met" in new_[prefix]:
                del new_[prefix]["Met"]
            if "Metric" in new_[prefix]:
                del new_[prefix]["Metric"]
            if not prefix in old_:
                adds[prefix] = new_[prefix]
            else:
                if new_[prefix] != old_[prefix]:
                    adds[prefix] = new_[prefix]
        for prefix in old_:
            if not prefix in new_:
                dels[prefix] = old_[prefix]
            else:
                if new_[prefix] != old_[prefix]:
                    dels[prefix] = old_[prefix]
        fib_changed = False
        if len(adds) + len(dels) > 0 or len(new_) == 0:
            self.data["kernel_fib"]["update_time"] = t0
            self.data["kernel_fib"]["data"] = new_
            # self.logger.debug(f"kernel fib changed")
            # self.logger.debug(f"adds:{adds}")
            # self.logger.debug(f"dels:{dels}")
            fib_changed = True
        for k, v in new_.items():
            self.logger.debug(f"{k}:{v}")
        for k, v in self.parse_kernel_fib3().items():
            self.logger.debug(f"{k}:{v}")
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
        self._generate_default_sav_rules()
        self.logger.debug(f"adds:{adds}")
        self.logger.debug(f"dels:{dels}")

        return adds, dels

    def _generate_default_sav_rules(self):
        local_prefixes = self.get_local_prefixes()
        local_device = "eth_veth"
        self.default_rules = []
        for p in local_prefixes:
            self.default_rules.append(get_sav_rule(p, local_device, "default"))

    def _initial_wait(self) -> None:
        """
        1. wait for bird to be ready
        2. wait for fib to be stable
        3. wait for aspa and roa info to be ready if rpki is enabled
        """
        t0 = time.time()
        while not self.bird_man.is_bird_ready():
            time.sleep(0.1)
            # self.logger.debug("waiting for bird to be ready")
        self.logger.debug("bird ready")
        while not self.data["metric"]["initial_fib_stable"]:
            # wait for fib to first fib stable
            self._refresh_both_fib()
            time.sleep(3)
        self.logger.debug("fib stable")
        if self.config["enable_rpki"]:
            self._refresh_aspa_info()
            while self.data["aspa_info"] == {}:
                time.sleep(5)
                self._refresh_aspa_info()
            self.logger.debug("got aspa")
            self._refresh_roa_info()
            while self.data["roa_info"] == {}:
                time.sleep(5)
                self._refresh_roa_info()
            self.logger.debug("got roa")

        self._init_apps()
        self.logger.debug(f"initial wait: {time.time()-t0:.4f} seconds")

    def get_adj_in(self, protocol_name):
        adj_info = copy.deepcopy(self.data["adj_in"][protocol_name])
        return

    def _refresh_adj_in(self):
        for l_name, l_meta in self.link_man.get_all_link_meta().items():
            if l_meta["link_type"] in ["dsav"]:
                proto_name = l_meta["protocol_name"]
                ret = birdc_get_import(
                    self.logger, proto_name, f"ipv{self.config['auto_ip_version']}")
                self.data["adj_in"][proto_name] = ret

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

    def _start_fib_monitor(self) -> None:
        """
        start a thread to monitor the fib change
        """
        with IPRoute() as ipr:
            ipr.bind()
            self.logger.debug("fib monitor started")
            while True:
                found = False
                for event in ipr.get():
                    if event["event"] in ["RTM_NEWROUTE", "RTM_DELROUTE", "RTM_NEWNEIGH"]:
                        found = True
                        self.logger.debug(event)
                    else:
                        self.logger.warning(event)
                if found:
                    self.logger.debug("fib changed")
                    self._refresh_fibs_notify_apps()

    def _start_main(self):
        """
        start a thread to check the cmd queue and process each cmd
        """
        self._initial_wait()
        # generate initial sav rules
        self.logger.debug(f"before initial fib")
        fib_adds = self.get_fib("kernel", ["remote", "local"])
        self.logger.debug(f"initial fib:{fib_adds}")
        bird_adds = self.get_fib("bird", ["remote", "local"])
        self._notify_apps(True, fib_adds, {}, bird_adds, {})
        self.logger.debug("starting main loop")
        while True:
            try:
                try:
                    if self.rpdp_app:
                        self.rpdp_app.send_spa_init()
                    msgs = []
                    # we first detect all native bgp update,
                    # if we detect one native bgp update, we insert a msg to trigger the kernel fib update
                    bgp_update_msg = None
                    msg0 = self._in_msgs.get()
                    bgp_update_msg, msgs = self._precheck_msg(
                        msg0, bgp_update_msg, msgs)
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

    def get_app(self, app_id):
        return self.data["apps"][app_id]

    def get_all_app_ids(self):
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
        local_prefixes = list(self.get_fib("kernel", ["local"]).keys())
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
        if link_name.startswith("rpki"):
            # TODO: handle rpki link state change
            # currently, we don't do anything
            return
        if not new_state == self.link_man.get_link_state(link_name):
            self.link_man.update_link_kv(link_name, "state", new_state)
            self.logger.info(f"link {link_name} state changed to {new_state}")
            if new_state is False:
                # reset initial_broadcast status
                self.link_man.update_link_kv(
                    link_name, "initial_broadcast", False)
        if self.passport_app:
            self.passport_app.init_key_publish()

    def _process_sav_intra(self, msg, link_meta):
        """
        doing nothing but logging
        """
        self.logger.info(
            f"GOT INTRA-MSG ON [{link_meta['protocol_name']}]:{msg}, time_stamp: [{time.time()}]")
        if link_meta["is_interior"]:
            self.logger.error("intra-msg received on inter-link!")

    def get_fib(self, source="kernel", f_types=["remote"]):
        """
        @param source: one of ["kernel","bird"]
        @param f_types: a list of data you want to include, element can be one of ["remote","local","default"]
        """
        if not source in ["kernel", "bird"]:
            self.logger.error(
                f"invalid source:{source}, should be one of [kernel,bird]")
            return {}
        for t in f_types:
            if not t in ["remote", "local", "default"]:
                self.logger.error(
                    f"invalid element:{t}, should be one of [remote,local,default]")
                return {}
        r_flag = "remote" in f_types
        l_flag = "local" in f_types
        d_flag = "default" in f_types
        data = {}
        if source == "kernel":
            temp = self._get_kernel_fib()
            # self.logger.debug(temp)
            # self.logger.debug(source)
            # self.logger.debug(f_types)
            for p, p_d in temp.items():
                if p.version == 4:
                    if p_d["Gateway"] == "0.0.0.0":
                        if l_flag:
                            data[p] = p_d
                    else:
                        if r_flag:
                            data[p] = p_d
                elif p.version == 6:
                    # self.logger.debug(p_d)
                    if p_d["Next"] == "::":
                        if l_flag:
                            data[p] = p_d
                    else:
                        if r_flag:
                            data[p] = p_d
                else:
                    self.logger.error(f"invalid ip version:{p.version}")
        else:
            temp = self.bird_man.get_fib()
            for p, p_d in temp.items():
                device_flag = False
                bgp_flag = False
                static_flag = False
                for src in p_d:
                    if not "type" in src:
                        self.logger.error(src)
                        self.logger.error(f"{p}:{p_d}")
                        continue
                    if src["type"] == "device univ":
                        device_flag = True
                    if src["type"] == "BGP univ":
                        bgp_flag = True
                    if src["type"] == "static univ":
                        static_flag = True
                if static_flag or device_flag:
                    if l_flag:
                        data[p] = [i for i in p_d if i["type"] != "BGP univ"]
                elif bgp_flag:
                    if r_flag:
                        # leave only bgp
                        data[p] = [i for i in p_d if i["type"] == "BGP univ"]
                else:
                    self.logger.warning("no type found")
                    self.logger.warning(f"{p}:{p_d}")
        # self.logger.debug(data)
        data = self._prefix_filter(data)
        # self.logger.debug(data)
        ret = {}
        default_routes = [netaddr.IPNetwork(
            "0.0.0.0/0"), netaddr.IPNetwork("::/0")]
        for p in data:
            if p in default_routes:
                if d_flag:
                    ret[p] = data[p]
            else:
                ret[p] = data[p]
        # self.logger.debug(ret)
        return ret

    def _get_kernel_fib(self):
        """return the cached fib"""
        return self.data["kernel_fib"]["data"]

    def _prefix_filter(self, prefixes):
        """
        """
        if not self.config["use_ignore_nets"]:
            return prefixes
        ret = {}
        if self.config["ignore_private"]:
            temp = {}
            for p in prefixes:
                if not p.is_private():
                    temp[p] = prefixes[p]
            prefixes = temp
        for p in prefixes:
            ignore = False
            for p1 in self.ignore_prefixes:
                if p in p1:
                    ignore = True
                    break
            if not ignore:
                ret[p] = prefixes[p]
        # TODO special filter in ipv6
        temp = {}
        for p in ret:
            if p.version == 4:
                temp[p] = ret[p]
            elif p.version == 6:
                if 'Hop' in ret[p]:
                    if ret[p]['Hop'] in ["Un", "U"]:
                        continue
                temp[p] = ret[p]
        ret = temp
        return ret

    def _refresh_both_fib(self):
        """
        refresh both kernel fib and bird fib
        return is_bird_fib_changed, is_kernel_fib_change, fib_adds, fib_dels, bird_adds,bird_dels
        """
        fib_adds, fib_dels = self._refresh_kernel_fib()
        is_bird_fib_changed, bird_adds, bird_dels = self.bird_man.update_fib(
            self.config["local_as"])
        is_kernel_fib_change = ((len(fib_adds) != 0) or (len(fib_dels) != 0))
        self._refresh_adj_in()
        return is_bird_fib_changed, is_kernel_fib_change, fib_adds, fib_dels, bird_adds, bird_dels

    def _process_native_bgp_update(self) -> None:
        """
        notify apps about native bgp update
        """
        self.logger.debug("processing native bgp update")
        self._refresh_fibs_notify_apps()

    def _refresh_fibs_notify_apps(self) -> None:
        """
        refresh both fibs and notify apps if fibs changed
        """
        bird_changed, kernel_changed, fib_adds, fib_dels, bird_adds, bird_dels = self._refresh_both_fib()
        # now we have the latest fib in kernel and bird
        if bird_changed != kernel_changed:
            self.logger.warning("bird fib and kernel fib change inconsistent")
            self.logger.debug(f"bird_adds:{bird_adds}")
            self.logger.debug(f"bird_dels:{bird_dels}")
            self.logger.debug(f"fib_adds:{fib_adds}")
            self.logger.debug(f"fib_dels:{fib_dels}")
            self.logger.debug(bird_changed)
            self.logger.debug(kernel_changed)
        if bird_changed or kernel_changed:
            self._notify_apps(False, fib_adds, fib_dels, bird_adds, bird_dels)

    def _notify_apps(self, reset, fib_adds, fib_dels, bird_adds, bird_dels, app_list=None):
        """
        notify sav_apps to generate sav rules
        if reset is True, it will clear all existing rules and re-generate all rules(the fib_adds and fib_dels will be ignored)
        if app_list is None, all apps will be notified.
        """
        self.logger.debug(f"fib_dels:{fib_dels}")
        self.logger.debug(f"bird_dels:{bird_dels}")
        if app_list is None:
            app_list = self.get_all_app_ids()
        self.logger.debug(f"app list:{app_list}")
        if reset is True:
            self.logger.debug(f"resetting sav table")
            self._init_sav_table()
        for app_id in app_list:
            app = self.get_app(app_id)
            self.logger.debug(f"notifying app: {app_id}")
            app_type = type(app)
            try:
                add_dict = {}
                del_list = []
                if app_type in [RPDPApp]:
                    # although the normal bgp update will not trigger rpdp, we still need to notify rpdp
                    # rpdp's generate_sav_rules will handle the rule modifications
                    self.rpdp_app.generate_sav_rules(reset)
                else:
                    # app_type in [UrpfApp, EfpUrpfApp, FpUrpfApp]:
                    add_dict, del_list = app.generate_sav_rules(
                        fib_adds, fib_dels, bird_adds, bird_dels, self.get_sav_rules_by_app(app_id))
                    # TODO filter
                    if self.config["use_ignore_nets"]:
                        temp = {}
                        for r_k, r in add_dict.items():
                            found = False
                            for p in self.ignore_prefixes:
                                if r['prefix'] in p:
                                    found = True
                                    break
                            if not found:
                                temp[r_k] = r
                        add_dict = temp
                    # self.logger.debug(f"add_dict:{add_dict}")
                    # self.logger.debug(f"dels:{del_list}")
                    self.update_sav_table_by_app_id(add_dict, del_list, app_id)
            except Exception as e:
                self.logger.exception(e)
                self.logger.error(f"error when notifying app {app_id}")

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
                self.logger.info(f"SAV_RULE - :{r}")
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
                self.logger.info(f"SAV_RULE + :{r}")
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
                self.logger.info(f"SAV_RULE REFRESHED:{r}")
        self.data["sav_table"] = new_table

    def update_sav_table_by_app_id(self, add_dict, del_set, app_id):
        """
        update sav table
        """
        cur_t = time.time()
        if not app_id in self.data["sav_table"]:
            new_table = {}
        else:
            new_table = copy.deepcopy(self.data["sav_table"][app_id])
        for str_key in del_set:
            if not str_key in new_table:
                self.logger.error(
                    f"key missing in sav_table (old):{str_key} in {new_table.keys()}")
            else:
                r = new_table[str_key]
                del new_table[str_key]
                self.logger.info(f"SAV_RULE - :{r}")
        for str_key, r in add_dict.items():
            if not str_key in new_table:
                r["create_time"] = cur_t
                r["update_time"] = cur_t
                new_table[str_key] = r
                self.logger.info(f"SAV_RULE + :{r}")
            else:
                old_r = new_table[str_key]
                r["create_time"] = old_r['create_time']
                r["update_time"] = old_r['update_time']
                if r == old_r:
                    self.logger.error(
                        f"conflict in sav_table (old):{old_r}")
                    self.logger.error(f"conflict in sav_table (new):{r}")
                    self.logger.error(f"app_id:{app_id}")
                else:
                    r["update_time"] = cur_t
                new_table[str_key] = r
                self.logger.info(f"SAV_RULE REFRESHED:{r}")
        self.data["sav_table"][app_id] = new_table

    def _get_sav_rules_by_app(self, app_name, include_default, is_interior=None):
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
        if include_default:
            for r in self.default_rules:
                str_key = get_key_from_sav_rule(r)
                if not str_key in all_rules:
                    all_rules[str_key] = r
        if is_interior is None:
            return all_rules
        temp = {}
        for k, v in all_rules.items():
            if v["is_interior"] == is_interior:
                temp[k] = v
        return temp

    def _expand_sav_rule(self, sav_rule, all_interfaces):
        """
        expand sav rule with all interfaces
        """
        ret = {}
        for ifa in all_interfaces:
            new_rule = copy.deepcopy(sav_rule)
            new_rule["interface_name"] = ifa
            ret[get_key_from_sav_rule(new_rule)] = new_rule
        return ret

    def get_sav_rules_by_app(self, app_name, is_interior=None, ip_version=None, include_default=True):
        """
        return all sav rules for given app
        if is_interior is None, return all rules
        if is_interior is True, return all interior rules
        if is_interior is False, return all exterior rules
        if any rules interface is * we will expand it to all interfaces
        if ip_version is None(default), return all rules,otherwise return rules with given ip_version
        return a dict of sav rules
        """
        temp = self._get_sav_rules_by_app(
            app_name, include_default, is_interior)
        all_interfaces = get_host_interface_list()
        ret = {}
        for k, v in temp.items():
            if ip_version is None:
                pass
            else:
                if v["prefix"].version != ip_version:
                    continue
            if v["interface_name"] == "*":
                for expanded_k, expanded_v in self._expand_sav_rule(v, all_interfaces).items():
                    ret[expanded_k] = expanded_v
            else:
                ret[k] = v
        ret = dict(sorted(ret.items()))
        return ret

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
            pp = self.get_fib("bird", ["remote"])
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
            self.logger.debug("rpdp_app missing, unable to send origin")
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

    def _process_msg(self, input_msg) -> None:
        input_msg["schedule_dt"] = time.time()
        t0 = input_msg["schedule_dt"]
        # self.logger.debug(input_msg)
        log_msg = f"start msg, pkt_id:{input_msg['pkt_id']}, msg_type: {input_msg['msg_type']}"
        key_types = [("msg_type", str), ("pkt_id", int), ("pkt_rec_dt", float)]
        keys_types_check(input_msg, key_types)
        msg, m_t = input_msg["msg"], input_msg["msg_type"]
        match m_t:
            case "link_state_change":
                self._process_link_state_change(input_msg)
            case "bird_bgp_config":
                # TODO for faster performance
                pass
            case "bgp_update":
                self._process_native_bgp_update()
            case "rpdp_update":
                # self.logger.debug(f"rpdp_update:{msg}")
                link_name = input_msg["source_link"]
                link_meta = self.link_man.get_by_name(link_name)
                self.rpdp_app.process_spa(input_msg, link_meta)
            case "rpdp_route_refresh":
                link_name = input_msg["source_link"]
                link_meta = self.link_man.get_by_name(link_name)
                self.rpdp_app.process_spd(input_msg, link_meta)
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
        # if not m_t.startswith("Passport"):
        self._update_sav_rule_nums()
        # self.logger.debug(f"finished")

    def _update_sav_rule_nums(self) -> None:
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
            self.logger.debug(f"SAV_RULE NUMS: {metric['total']}")

    def _get_spd_id(self, remote_as, remote_router_id):
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
            self.logger.debug("rpdp_app missing, unable to send spd")
            return False
        # here the remote refers to prefixes that are not originated by this router
        possible_prefixes = self.get_fib("bird", ["remote"])
        inter_as_links = {}
        for link_name in self.link_man.get_all_up_type(True, False):
            inter_as_links[link_name] = self.link_man.get_by_name(link_name)

        temp = {}
        intra_as_links = {}
        my_as_prefixes = {}
        as_neighbors = {}
        # self.logger.debug(inter_as_links)
        # self.logger.debug(possible_prefixes)
        for prefix, srcs in possible_prefixes.items():
            # self.logger.debug(f"{prefix}:{srcs}")
            my_asn_prefix = False

            for src in srcs:
                if src["origin_asn"] == my_asn:
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
                            as_neighbors[src["origin_asn"]].append(
                                src["as_path"][x+1])
                        except IndexError:
                            pass
                        try:
                            as_neighbors[src["origin_asn"]].append(
                                src["as_path"][x-1])
                        except IndexError:
                            pass
            if my_asn_prefix:
                my_as_prefixes[prefix] = srcs

        self.rpdp_app.send_spd(inter_as_links, as_neighbors, my_as_prefixes,
                               self.config["local_as"], self.config["router_id"])
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
                                # self.logger.debug(
                                # "fib not stable, not sending spd")
                                continue
                            self._send_spd()
                        else:
                            self.logger.warning(
                                f"unknown event:{event}, skipping")
            time.sleep(0.5)

    def _start(self) -> None:
        self._thread_pool = []
        self._thread_pool.append(threading.Thread(target=self._start_main))
        self._thread_pool.append(threading.Thread(target=self.link_man._run))
        self._thread_pool.append(threading.Thread(
            target=self._interval_trigger))
        self._thread_pool.append(threading.Thread(
            target=self._start_fib_monitor))
        for t in self._thread_pool:
            t.daemon = True
            t.start()
        # self._start_fib_monitor()

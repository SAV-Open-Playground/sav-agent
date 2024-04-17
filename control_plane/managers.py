# -*-coding:utf-8 -*-
'''
@File    :   managers.py
@Time    :   2023/01/17
@Version :   0.1

@Desc    :   the managers.py is responsible for the execution of selected sav mechanism and other manager classes
'''
import queue
import copy
from common import *
from sav_app import *


class BirdCMDManager():
    """manage the execution of bird command, avoid concurrency issue"""

    def __init__(self, logger) -> None:
        self.logger = logger
        self.cmd_list = []
        self.is_running = False
        self.bird_fib = {"check_time": None, "update_time": None, "fib": {}}

    def is_bird_ready(self):
        """
        return True if bird is ready
        """
        try:
            result = self.bird_cmd("show status", log_err=False)
            if result:
                return True
            else:
                return False
        except:
            return False

    def bird_cmd(self, cmd, log_err=True):
        while self.is_running:
            time.sleep(0.01)
        self.is_running = True
        ret = birdc_cmd(self.logger, cmd, log_err)
        self.is_running = False
        return ret

    def get_by_remote_as_is_inter(self, remote_as, is_interior):
        result = []
        for link_name, data in self.protos["links"].items():
            if "meta" not in data:
                continue
            if not data["meta"]:
                continue
            meta = data["meta"]
            if (meta["remote_as"] == remote_as) and (
                    meta["is_interior"] == is_interior):
                result.append(meta)
        return result

    def get_up_inter_links(self):
        result = {}
        for proto, data in self.protos["links"].items():
            if data["meta"]["is_interior"]:
                result[proto] = data
        return result

    def get_proto(self, proto_name):
        if not proto_name in self.protos:
            raise ValueError(
                f"proto_name {proto_name} not found in {list(self.protos.keys())}")
        return self.protos.get(proto_name, None)

    def _parse_next_level(self, raw_input, indent=2):
        # self.logger.debug(json.dumps(raw_input, indent=2))
        result = {}
        last_key = None
        special_cases = ["Description", "Neighbor AS", "Local AS",
                         "Neighbor address", "Role", "Source address"]
        for line in raw_input:
            # self.logger.debug(line)
            if line.startswith(" " * indent):
                if last_key is None:
                    self.logger.error("last_key is None")
                    self.logger.error(line)
                    continue
                result[last_key].append(line[indent:])
            else:
                line = line.strip()
                found = False
                for k in special_cases:
                    if line.startswith(k):
                        key, value = line.split(":")
                        if key in result:
                            self.logger.error(f"key {key} already exists")
                            self.logger.error(line)
                            continue

                        result[key] = value.strip()
                        found = True
                        break
                if not found:
                    result[line] = []
                last_key = line
        for k, v in result.items():
            if type(v) == list:
                result[k] = self._parse_next_level(v, indent=indent)
        return result


    def update_bird_fib(self, my_asn, log_err=True):
        """
        return if changed and a dict of changes
        """
        self.bird_fib["check_time"] = time.time()
        new_data = self._parse_bird_fib(log_err, my_asn)
        something_updated = False
        adds, dels = self._diff_fib(self.bird_fib["fib"], new_data)
        if len(adds) + len(dels) > 0:
            something_updated = True
            self.bird_fib["fib"] = new_data
        if something_updated:
            self.logger.debug(f"BIRD something_updated")
            self.bird_fib["update_time"] = self.bird_fib["check_time"]
        return something_updated, adds, dels

    def _diff_fib(self, old_fib, new_fib):
        """
        return list of added and deleted rows in dict format

        """
        # self.logger.debug(f"old fib:{old_fib}, new_fib:{new_fib}")
        dels = {}
        adds = {}
        # skip_keys = ["time"]
        for prefix in new_fib:
            old_data = old_fib.get(prefix, None)
            if not (new_fib.get(prefix, None) == old_fib.get(prefix, None)):
                adds[prefix] = new_fib[prefix]
        for prefix in old_fib:
            if not (new_fib.get(prefix, None) == old_fib.get(prefix, None)):
                dels[prefix] = old_fib[prefix]
        return adds, dels

    def get_fib(self):
        return copy.deepcopy(self.bird_fib["fib"])

    def pre_process_table(self, table):
        """
        format the out put for latter use
        only tested in iBGP with IPv6
        """
        temp = {}
        for table_name, table_value in table.items():
            temp[table_name] = {}
            for prefix, data in table_value.items():
                temp[table_name][prefix] = {}
                for k, v in data.items():
                    new_k = k
                    if new_k.startswith("bgp"):
                        new_k = new_k[4:]
                    if new_k.endswith(":"):
                        new_k = new_k[:-1]
                    temp[table_name][prefix][new_k] = v
        del table
        return temp

    # def _parse_remote_prefix_data(self, prefix_data):
    #     self.logger.debug(prefix_data)
    #     interface = None
    #     remote_ip = None
    #     for k in prefix_data:
    #         if k.startswith("via "):
    #             temp = k.split()
    #             interface = temp[-1]
    #             remote_ip = temp[1]
    #             break
    #         if k == "via":
    #             if ' on ' in prefix_data[k]:
    #                 temp = prefix_data[k].split()
    #                 interface = temp[-1]
    #                 remote_ip = temp[0]
    #                 break
    #     prefix_data["interface"] = interface
    #     # self.logger.debug(remote_ip)
    #     prefix_data["remote_ip"] = netaddr.IPAddress(remote_ip)
    #     # self.logger.debug(prefix_data)
    #     return prefix_data

    # def _tell_prefix(self, prefix, prefix_srcs, my_asn):
    #     """
    #     tell if prefix is a local remote or default
    #     local: the prefixes that I will broadcast
    #     remote: the prefixes that I learned from other device
    #     default: the default route
    #     """
    #     device_flag = False
    #     bgp_flag = False
    #     static_flag = False
    #     if prefix.prefixlen == 0:
    #         return "default"
    #     for src in prefix_srcs:
    #         if not "type" in src:
    #             self.logger.error(src)
    #             self.logger.error(prefix)
    #             continue
    #         if src["type"] == "device univ":
    #             device_flag = True
    #         if src["type"] == "LINK_BGP univ":
    #             bgp_flag = True
    #         if src["type"] == "static univ":
    #             static_flag = True
    #     if static_flag:
    #         return "local"
    #     if device_flag:
    #         return "local"
    #     if bgp_flag:
    #         return "remote"
    #     self.logger.error("unable to tell")
    #     self.logger.error(src)
    #     self.logger.error(prefix)

    def _parse_bird_fib(self, log_err, my_asn):
        """
        using birdc show all to get bird fib,
        """
        t0 = time.time()
        new_data = {}
        # self.logger.debug("show route all")
        data = self.bird_cmd("show route all", log_err)
        # self.logger.debug([data])
        if data is None:
            return new_data
        try:
            data = parse_bird_show_route_all(data, my_asn)
        except Exception as e:
            self.logger.error(e)
            self.logger.exception(e)
            raise e
        have_master = False
        if "master4" in data:
            have_master = True
        if "master6" in data:
            have_master = True
        if not have_master:
            self.logger.debug([data])
            self.logger.error(
                "no master table. Is BIRD ready?")
            raise ValueError("no master table. Is BIRD ready?")

        for table_name, table_value in data.items():
            for prefix, srcs in table_value.items():
                if prefix in new_data:
                    self.logger.error(f"prefix {prefix} already exists")
                else:
                    # temp = []
                    # for src in srcs:
                    #     self.logger.debug(src)
                    #     if "pro"
                    #     if src["type"] == "LINK_BGP univ":
                    #         temp.append(src)
                    new_data[prefix] = srcs
        t = time.time() - t0
        if t > TIMEIT_THRESHOLD:
            self.logger.warning(f"TIMEIT {time.time() - t0:.4f} seconds")
        return new_data
class InfoManager():
    """
    info manager manage the info of stored data,
    base class for SavAgent and SavApp.
    """

    def __init__(self, data, logger):
        if not isinstance(data, dict):
            raise ValueError("data is not a dictionary")
        self.logger = logger
        self.data = data

    def add(self, msg):
        raise NotImplementedError

    def delete(self, key):
        raise NotImplementedError

    def get(self, key):
        raise NotImplementedError

    def update(self, key, value):
        raise NotImplementedError

    def add_update(self, key, value):
        raise NotImplementedError

    def is_up(self, key):
        raise NotImplementedError

    def get_all_up(self):
        raise NotImplementedError


class LinkManager(InfoManager):
    """
    LinkManager manage the link status and preprocessing the msg from the link
    link_name is key MUST be unique
    the link_name should be generated using _get_link_name() function
    the bird command function is also here
    """

    # TODO: we have three types of link: native bgp, modified bgp and grpc

    def __init__(self, data, agent, logger):
        super(LinkManager, self).__init__(data, logger)
        self._send_buff = queue.Queue()
        self.bird_cmd_buff = queue.Queue()
        self.post_session = requests.Session()
        self.post_session.keep_alive = True
        self.result_buff = {}
        self._job_id = 0
        self._add_lock = False
        self.agent = agent
        self.valid_types = [LINK_NATIVE_BGP, LINK_RPDP_BGP, LINK_RPDP_HTTP,LINK_BGP_WITH_RPDP]
        self.add_sa_cfg_links(agent.config)
        self.bird_man = BirdCMDManager(logger)

    def recv_http_post(self, msg):
        self.logger.debug(f"recv_http_post got {msg}")

    def get_link_state(self, link_name):
        """
        return the state of the link
        """
        return self.data["links"][link_name]["status"]

    def get_by_name(self, name):
        """
        if found, return the deepcopy of the link meta
        """
        if not name in self.data["links"]:
            # self.logger.debug(self.data)
            raise ValueError(f"link {name} not found")
        try:
            return copy.deepcopy(self.data["links"][name])
        except Exception as e:
            self.logger.error(e)
            self.logger.exception(e)
            raise e

    def get_by_interface(self, interface):
        for name, data in self.data["links"].items():
            self.logger.debug(data)
            if data["interface_name"] == interface:
                return data
        raise ValueError(f"interface {interface} not found")

    def get_by_remote_ip(self, remote_ip):
        for name, data in self.data["links"].items():
            if data["remote_ip"] == remote_ip:
                return data
        # self.logger.debug(self.data["links"])
        raise ValueError(f"remote_ip {remote_ip} not found")

    def get_by_local_ip(self, local_ip):
        for name, data in self.data["links"].items():
            if data["local_ip"] == local_ip:
                return data
        # self.logger.debug(self.data["links"])
        raise ValueError(f"local_ip {local_ip} not found")

    def put_send_async(self, msg) -> None:
        """
        timeout is in seconds, if set to 0, then will keep trying until sent
        "retry" is optional, if set, then will retry for the given times (default is 10)
        """
        # check if msg is valid
        # self.logger.debug(f"put_send_async got {msg}")
        key_types = [("msg_type", str), ("data", dict), ("source_app", str),
                     ("timeout", int), ("store_rep", bool)]
        keys_types_check(msg, key_types)
        # self.logger.debug(f"passed key_types_check")
        supported_type = [LINK_RPDP_HTTP, LINK_RPDP_BGP,LINK_BGP_WITH_RPDP]
        if not msg["msg_type"] in supported_type:
            raise ValueError(
                f"unknown msg type {msg['msg_type']} / {supported_type}")
        supported_apps = [RPDP_ID, "passport_app"]
        if not msg["source_app"] in supported_apps:
            raise ValueError(
                f"unknown msg source_app {msg['source_app']} / {supported_apps}")
        msg["pkt_id"] = self._job_id
        msg["created_dt"] = time.time()
        self._send_buff.put(msg)
        self._job_id += 1
        # do not remove this line. This line will trigger the sending process of the message
        self._send_buff.qsize()
        # self.logger.info(
        # f"send_trigger PLEASE IGNORE: {self._send_buff.qsize()}")

    def put_send_sync(self, msg):
        """
        will return response
        """
        raise NotImplementedError

    def add_sa_cfg_links(self, sa_config) -> None:
        """
        read link meta from bird config, call if needed
        """
        my_asn = sa_config["local_as"]
        temp = {}
        for proto_name, cfg_link in sa_config["link_map"].items():
            # self.logger.debug(proto_name)
            link_meta = {
                "initial_broadcast": False,
                "as4_session": True,
                "protocol_name": proto_name,
                "status": True,
                "interface_name": f"eth_{proto_name.split('_')[2]}",
                "remote_ip": netaddr.IPAddress(cfg_link["remote_ip"]),
                "local_ip": netaddr.IPAddress(cfg_link["local_ip"]),
                "remote_role": cfg_link['remote_role'],
                "local_role": cfg_link['local_role'],
                "remote_as": cfg_link['remote_as']
            }
            link_meta["is_interior"] = link_meta["remote_as"] != sa_config["local_as"]
            if not cfg_link["link_type"] in self.valid_types:
                self.logger.error(f"unsupported value:{cfg_link['link_type']}")
                continue
            link_meta["link_type"] = cfg_link["link_type"]
            temp["_".join(
                [link_meta["link_type"], sa_config['device_id'], cfg_link['remote_id']])] = link_meta
        self.data["check_time"] = time.time()
        self.data["links"] = temp
        self.data["update_time"] = self.data["check_time"]

    def get_all_link_meta(self):
        result = copy.deepcopy(self.data["links"])
        return result

    def get_all_bgp_links(self) -> dict:
        """return a dict of all bgp links
        key is link_name, value is link_meta
        """
        result = {}
        for name, data in self.data["links"].items():
            if data["link_type"] in ["bgp"]:
                result[name] = data
        return result

    def get_all_rpdp_links(self) -> dict:
        """return a dict of all rpdp links
        key is link_name, value is link_meta
        """
        result = {}
        for name, data in self.data["links"].items():
            # self.logger.debug(name)
            # self.logger.debug(data["link_type"])
            # self.logger.debug(RPDP_LINK_TYPES)
            if data["link_type"] in RPDP_LINK_TYPES:
                result[name] = data
        return result

    def _update_metric(self, d, msg):
        send = d["send"]
        send["count"] += 1
        send["size"] += len(str(msg["data"]))
        send["time"] += msg["finished_dt"] - msg["schedule_dt"]
        send["wait_time"] += msg["schedule_dt"] - msg["created_dt"]
        if d["start"] is None:
            d["start"] = msg["created_dt"]
        d["end"] = msg["finished_dt"]
        return d

    def send_msg(self, msg) -> None:
        # self.logger.debug(msg)
        msg["schedule_dt"] = time.time()
        m_t = msg["msg_type"]
        if m_t == LINK_RPDP_HTTP:
            sent = self._send_http_post(msg)
            if not sent:
                self.logger.debug(sent)
        elif m_t == LINK_RPDP_BGP:
            # self.logger.debug(msg["data"])
            desired_link_name = msg["data"]["protocol_name"]
            link = self.data["links"].get(desired_link_name, None)
            if not link:
                self.logger.error(
                    f"link {desired_link_name} not found in {self.data['links']}")
                sent = False
                return
            if not link["link_type"] in [LINK_RPDP_BGP,LINK_BGP_WITH_RPDP]:
                self.logger.error(
                    f"link {desired_link_name} is not {LINK_RPDP_BGP}")
                sent = False
                return
            # self.logger.debug(msg["data"])
            self.bird_cmd_buff.put(msg["data"])
            try:
                msg["call_agent_msg_dt"] = time.time()
                self.agent.bird_man.bird_cmd("call_agent")
                sent = True
            except Exception as e:
                self.logger.exception(e)
                sent = False
        else:
            raise NotImplementedError
        msg["finished_dt"] = time.time()
        # update_metric
        if msg["source_app"] == RPDP_ID:
            temp = self._update_metric(
                self.agent.rpdp_app.metric[m_t], msg)
            self.agent.rpdp_app.metric[m_t] = temp
        else:
            raise ValueError(f"unknown msg source_app {msg['source_app']}")
        if not sent:
            self.logger.warning(f"send failed {msg}")
            self.send_buff.append(msg)
        else:
            pass
            # self.logger.debug(f"send success {msg}")

    def _send_http_post(self, msg):
        # if msg["timeout"] == 0: will keep trying until sent
        # self.logger.debug(msg)
        if msg["timeout"] == 0:
            while True:
                rep = self.post_session.post(
                    msg["url"], data=pickle.dumps(msg["data"]), timeout=3)
                if rep.status_code == 200:
                    if msg["store_rep"]:
                        self.result_buff[msg["pkt_id"]] = rep.json()
                    return True
        if not "retry" in msg:
            retry = 10
        for i in range(retry):
            rep = self.post_session.post(
                msg["url"], data=pickle.dumps(msg["data"]), timeout=msg["timeout"])
            if rep.status_code == 200:
                self.result_buff[msg["pkt_id"]] = rep.json()
                return True
            time.sleep(msg["timeout"])
        return False

    def add(self, meta_dict):
        self._is_good_meta(meta_dict)
        # self.logger.debug(f"adding {meta_dict}")
        link_type = meta_dict["link_type"]
        link_name = self._get_link_name(meta_dict)
        # self.logger.debug(f"adding {link_name}")
        if link_name in self.data:
            self.logger.warning(f"key {link_name} already exists")
            return
        if not link_type in ["bgp", "dsav"]:
            self.logger.error(f'unknown link_type: {link_type}')
            return
        self.data[link_name] = meta_dict
        self.logger.debug(f"link added: {link_name}")

    def _get_link_name(self, meta_dict):
        self.logger.debug(meta_dict)
        return meta_dict["protocol_name"]

    def update_link(self, meta_dict):
        self._is_good_meta(meta_dict)
        link_name = self._get_link_name(meta_dict)
        old_meta = self.data[link_name]
        if old_meta["status"] == meta_dict["status"]:
            return
        self.data[link_name] = meta_dict
        self.logger.debug(f"link updated: {self.data[link_name]} ")

    def get_rpdp_links(self, link_map):
        """return a list of link_name and link_data tuple that are rpdp links
        """
        results = []
        for link_name, link in self.data.items():
            # self.logger.debug(link["protocol_name"] )
            # self.logger.debug(link_map.keys() )
            if link["protocol_name"] in link_map:
                results.append((link_name, link))
            elif link["link_type"] == "dsav":
                results.append((link_name, link))
            else:
                self.logger.debug(f"ignoring no sav link: {link_name}")
        return results

    def get_all_up(self, include_native_bgp=False):
        """
        return a list of all up link_names ,use get(link_name) to get link object
        """
        temp = []
        for link_name, link in self.data["links"].items():
            # self.logger.debug(link)
            if link["status"]:
                if link["link_type"] == "bgp":
                    # self.logger.debug(link["protocol_name"])
                    if include_native_bgp:
                        temp.append(link_name)
                else:
                    temp.append(link_name)
        return temp

    def get_all_up_type(self, is_interior, include_native_bgp=False) -> list:
        """
        return a list of all up link_names with the correct type (is_interior or not),
        use get(link_name) to get link object
        """
        result = []
        for link_name in self.get_all_up(include_native_bgp):
            if self.data["links"][link_name]["is_interior"] == is_interior:
                result.append(link_name)
        return result

    def get_bgp_by_interface(self, interface_name):
        """
        return a list of bgp(modified or native) link_dict that has the same interface_name
        """
        result = []
        # self.logger.debug(self.data)
        for _, link in self.data.items():
            # self.logger.debug(link)
            if link["interface_name"] == interface_name:
                result.append(link)
        # self.logger.debug(f"result:{result}")
        return result

    def exist(self, link_name):
        return link_name in self.data

    def _is_good_meta(self, meta):
        key_types = [("remote_as", int), ("local_as", int),
                     ("remote_ip", str), ("local_ip", str),
                     ("local_role", str), ("remote_role", str),
                     ("interface_name", str), ("link_type", str),
                     ("protocol_name", str), ("as4_session", bool),
                     ("is_interior", bool), ("status", bool),
                     ("initial_broadcast", bool)]
        keys_types_check(meta, key_types)
        if not meta["link_type"] in ["bgp", "dsav"]:
            raise ValueError(f'unknown link_type: {meta["link_type"]}')
        return True

    def _run(self):
        """
        run in a separate thread, send msg in the send_buff
        """
        self.logger.debug("link manager started")
        while True:
            msg = self._send_buff.get()
            # self.logger.debug(msg)
            self.send_msg(msg)

    def update_link_kv(self, link_name, k, v):
        self.data["links"][link_name][k] = v

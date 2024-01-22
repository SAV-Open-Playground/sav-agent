# -*-coding:utf-8 -*-
'''
@File    :   managers.py
@Time    :   2023/01/17
@Version :   0.1

@Desc    :   the managers.py is responsible for the execution of selected sav mechanism and other manager classes
'''
import queue
import copy
from common.sav_common import *
from sav_app import *

class BirdCMDManager():
    """manage the execution of bird command, avoid concurrency issue"""

    def __init__(self, logger) -> None:
        self.logger = logger
        self.cmd_list = []
        self.is_running = False
        self.bird_fib = {"check_time": None, "update_time": None, "local_route": {},
                         "remote_route": {}, "default_route": {}}

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

    # def update_protocols2(self):
    #     """
    #     using birdc show protocols all to get bird protocols info, very slow
    #     """
    #     check_time = time.time()
    #     while True:
    #         raw_result = self.bird_cmd("show protocols all", False)
    #         if raw_result:
    #             new_ = self._parse_protocols(raw_result)
    #             all_good = True
    #             for p, d in new_.items():
    #                 if p.startswith("savbgp"):
    #                     if d["meta"] is None:
    #                         self.logger.warning(f"{p} meta is None")
    #                     all_good = False
    #             if all_good:
    #                 break
    #         time.sleep(0.1)
    #     return new_, check_time

    # def parse_link_meta(self, proto_data):
    #     """
    #     update link meta data
    #     """
    #     try:
    #         self.logger.debug(json.dumps(proto_data, indent=2))
    #         t = proto_data["links"]["BGP state:          Established"]
    #         meta = {
    #             "interface_name": t["Neighbor address"].split("%")[1],
    #             "remote_as": int(t["Neighbor AS"]),
    #             "local_role": t["Local capabilities"]["Role"],
    #             "local_as": int(t["Local AS"]),
    #             "local_ip": netaddr.IPAddress(t["Source address"]),
    #             "remote_ip": netaddr.IPAddress(t["Neighbor address"].split("%")[0]),
    #             "status": proto_data["State"] == "up",
    #             "initial_broadcast": False,
    #             "as4_session": "4-octet AS numbers" in t["Local capabilities"],
    #             "protocol_name": proto_data["Name"]
    #         }
    #         if RPDP_ID in str(t):
    #             meta["link_type"] = "dsav"
    #         else:
    #             meta["link_type"] = "native_bgp"
    #         meta["is_interior"] = (meta["remote_as"] != meta["local_as"])
    #         # self.logger.debug(json.dumps(meta, indent=2))
    #         return meta
    #     except KeyError as e:
    #         self.logger.error(e)
    #         self.logger.exception(e)
    #         return None

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

    def _parse_links(self, raw_input):
        """
        parse link data inside proto_data
        """
        for key1, data in raw_input.items():
            if not key1.startswith("savbgp"):
                continue
            temp = data["sub_1"]
            del raw_input[key1]["sub_1"]
            result = self._parse_next_level(temp)
            raw_input[key1]["links"] = result
            # self.logger.debug(json.dumps({key1: raw_input[key1]}, indent=2))
        return raw_input

    # def _parse_protocols(self, raw_input):
    #     lines = raw_input.split("\n")
    #     headings = lines.pop(0).split()
    #     result = {}
    #     this_proto = None
    #     for l in lines:
    #         if len(l) < 1:
    #             continue
    #         if not l.startswith(" "):
    #             current_headings = l.split()
    #             this_proto = current_headings[0]
    #             result[this_proto] = dict(
    #                 zip(headings, current_headings))
    #             # self.logger.debug(result[this_proto])
    #             result[this_proto]["sub_1"] = []
    #         elif l.startswith("  "):
    #             result[this_proto]["sub_1"].append(l[2:])
    #         else:
    #             self.logger.error(f"unknown heading: {l}")
    #     result = self._parse_links(result)
    #     for p, d in result.items():
    #         if p.startswith("savbgp"):
    #             d["meta"] = self.parse_link_meta(d)
    #             result[p] = d
    #     return result

    def update_fib(self, my_asn, ignore_nets,log_err=True):
        """
        return if changed and a dict of changes
        """
        self.bird_fib["check_time"] = time.time()
        default, local, remote = self._parse_bird_fib(log_err, my_asn,ignore_nets)
        # self.logger.debug(f"_parse_bird_fib finished")
        something_updated = False
        local_adds, local_dels = self._diff_fib(
            self.bird_fib["local_route"], local)
        if len(local_adds) + len(local_dels) > 0:
            something_updated = True
            self.bird_fib["local_route"] = local
            # self.logger.debug(f"local_route updated")
        remote_adds, remote_dels = self._diff_fib(
            self.bird_fib["remote_route"], remote)
        if len(remote_adds) + len(remote_dels) > 0:
            something_updated = True
            self.bird_fib["remote_route"] = remote
            # self.logger.debug(f"remote_route updated")
        if default != self.bird_fib["default_route"]:
            # ignore default route change
            self.bird_fib["default_route"] = default
            # something_updated = True
            # self.logger.debug(f"default_route updated")
        if something_updated:
            self.logger.debug(f"BIRD something_updated")
            # self.logger.debug(f"local_adds:{local_adds}")
            # self.logger.debug(f"local_dels:{local_dels}")
            # self.logger.debug(f"remote_adds:{remote_adds}")
            # self.logger.debug(f"remote_dels:{remote_dels}")
            self.bird_fib["update_time"] = self.bird_fib["check_time"]
        return something_updated, {"local_adds": local_adds, "local_dels": local_dels, "remote_adds": remote_adds, "remote_dels": remote_dels}
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

    def get_local_fib(self):
        """"filter out local routes from fib"""
        return copy.deepcopy(self.bird_fib["local_route"])

    def get_remote_fib(self):
        """"filter out remote routes from fib"""
        return copy.deepcopy(self.bird_fib["remote_route"])

    def get_remote_local_fib(self):
        """"filter out remote and local routes from fib"""
        temp = {}
        for prefix, data in self.bird_fib["local_route"].items():
            temp[prefix] = data
        for prefix, data in self.bird_fib["remote_route"].items():
            temp[prefix] = data
        return temp

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
                    if new_k.startswith("BGP."):
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

    def _tell_prefix(self, prefix, prefix_srcs, my_asn):
        """
        tell if prefix is a local remote or default
        local: the prefixes that I will broadcast
        remote: the prefixes that I learned from other device
        default: the default route
        """
        device_flag = False
        bgp_flag = False
        static_flag = False
        if prefix.prefixlen == 0:
            return "default"
        for src in prefix_srcs:
            if not "type" in src:
                self.logger.error(src)
                self.logger.error(prefix)
                continue
            if src["type"] == "device univ":
                device_flag = True
            if src["type"] == "BGP univ":
                bgp_flag = True
            if src["type"] == "static univ":
                static_flag = True
        if static_flag:
            return "local"
        if device_flag:
            return "local"
        if bgp_flag:
            return "remote"
        self.logger.error("unable to tell")
        self.logger.error(src)
        self.logger.error(prefix)
    def _ignore_prefix(self, prefix, ignore_nets):
        for net in ignore_nets:
            if prefix in net:
                return True
        return False
    def _parse_bird_fib(self, log_err, my_asn,ignore_nets = []):
        """
        using birdc show all to get bird fib,
        """
        t0 = time.time()
        default = {}
        local = {}
        remote = {}
        # self.logger.debug("show route all")
        data = self.bird_cmd("show route all", log_err)
        # self.logger.debug([data])
        if data is None:
            return default, local, remote
        try:
            data = parse_bird_show_route_all(data, my_asn)
        except Exception as e:
            self.logger.error(e)
            self.logger.exception(e)
            raise e
        # self.logger.debug([data])
        have_master = False
        if "master4" in data:
            have_master = True
        if "master6" in data:
            have_master = True
        if not have_master:
            self.logger.error(
                "no master table. Is BIRD ready?")
            raise ValueError("no master table. Is BIRD ready?")

        for table_name, table_value in data.items():
            for prefix, data in table_value.items():
                if self._ignore_prefix(prefix,ignore_nets):
                    continue
                t = self._tell_prefix(prefix, data, my_asn)
                if t == "default":
                    default[prefix] = data
                elif t == "local":
                    local[prefix] = data
                elif t == "remote":
                    remote[prefix] = data
        t = time.time() - t0
        if t > TIMEIT_THRESHOLD:
            self.logger.warning(f"TIMEIT {time.time() - t0:.4f} seconds")
        return default, local, remote

    def _parse_bird_table(self, table):
        """
        return table_name (string) and parsed_rows (dict)
        """
        # self.logger.debug([table])
        t0 = time.time()
        temp = table.split("\n")

        table_name = temp[0][1:-1]
        parsed_rows = {}
        temp = temp[1:]
        rows = []
        this_row = []
        for line in temp:
            if not (line[0] == '\t' or line[0] == ' '):
                rows.append(this_row)
                this_row = [line]
            else:
                this_row.append(line)
        rows.append(this_row)
        while [] in rows:
            rows.remove([])
        # self.logger.debug(f"rows:{rows}")
        for row in rows:
            prefix = row.pop(0)
            # if "blackhole" in prefix:
            #     continue
            while "  " in prefix:
                prefix = prefix.replace("  ", " ")

            prefix_temp = prefix.split(" ")
            prefix = prefix_temp[0]
            if len(prefix) < 9:
                self.logger.error(f"incorrect prefix len: {row}")
            # self.logger.debug(prefix)
            # TODO check correctness
            if "-" in prefix:
                prefix = prefix.split("-")[0]
            prefix = netaddr.IPNetwork(prefix)
            # if prefix.version != ip_version:
            # continue
            # if prefix.is_private():
            #     # self.logger.debug(f"private prefix {prefix} ignored")
            #     continue
            #
            temp = {"meta": " ".join(prefix_temp[1:])}
            for line in row:
                if line.startswith("\t") and (":" in line):
                    line = line.strip()
                    line = line.split(": ")
                    k = line[0]
                    v = ":".join(line[1:])
                    # self.logger.debug(f"[{k}]:[{v}]")
                    if k in temp:
                        if not isinstance(temp[k], list):
                            temp[k] = [temp[k]]
                        temp[k].append(v)
                    else:
                        temp[k] = v
                    if k == "BGP.as_path":
                        # self.logger.debug(f"v:{v}")
                        if not "as_path" in temp:
                            temp["as_path"] = []
                        temp["as_path"].extend(list(map(int, v.split(" "))))
                        # self.logger.debug(f"as_path:{temp['as_path']}")
                        del temp["BGP.as_path"]
                elif line.startswith("\tdev"):
                    temp["interface"] = line.split(" ")[1]
                elif line.startswith("\tvia"):
                    temp["via"] = " ".join(line.split(" ")[1:])
                elif line.startswith("                     unicast"):
                    line = line.strip()
                    temp["source"] = line
                else:
                    self.logger.warning([line])
            if prefix in parsed_rows:
                self.logger.warning(f"prefix {str(prefix)} already exists")
            else:
                parsed_rows[prefix] = temp
        t = time.time() - t0
        if t > TIMEIT_THRESHOLD:
            self.logger.debug(f"TIMEIT {time.time() - t0:.4f} seconds")
        return table_name, parsed_rows


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

    def __init__(self, data, agent, logger=None):
        super(LinkManager, self).__init__(data, logger)
        self._send_buff = queue.Queue()
        self.bird_cmd_buff = queue.Queue()
        self.post_session = requests.Session()
        self.post_session.keep_alive = True
        self.result_buff = {}
        self._job_id = 0
        self._add_lock = False
        self.agent = agent
        self.read_brd_cfg(agent.config['local_as'])
        self.bird_man = BirdCMDManager(logger)

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
            self.logger.debug(self.data)
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

    def update_config(self, config):
        self.config = config

    def put_send_async(self, msg):
        """
        supported type : ["http-post","grpc","quic","dsav"]
        timeout is in seconds, if set to 0, then will keep trying until sent
        "retry" is optional, if set, then will retry for the given times (default is 10)
        """
        # check if msg is valid
        # self.logger.debug(f"put_send_async got {msg}")
        key_types = [("msg_type", str), ("data", dict), ("source_app", str),
                     ("timeout", int), ("store_rep", bool)]
        keys_types_check(msg, key_types)
        # self.logger.debug(f"passed key_types_check")
        supported_type = ["http-post", "dsav"]

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

    def read_brd_cfg(self, my_asn):
        """
        read link meta from bird config, call if needed
        """
        f = open("/usr/local/etc/bird.conf", "r")
        data = f.readlines()
        f.close()
        for i in range(len(data)):
            if data[i].startswith("protocol bgp savbgp"):
                data = data[i:]
                break
        temp = {}
        proto_name = None
        for l in data:
            l = l.strip()
            # self.logger.debug(l)
            if l.startswith("protocol"):
                l = l.split(" ")
                proto_name = l[2]
                meta = {
                    "initial_broadcast": False,
                    "as4_session": True,
                    "protocol_name": proto_name,
                    "status": True  # faster
                }
                if "sav_inter" in l:
                    meta["link_type"] = "dsav"
                elif "basic" in l:
                    meta["link_type"] = "native_bgp"
                else:
                    self.logger.error(f"unknown link type: {l}")
                temp[proto_name] = meta
            elif l.startswith("local role"):
                l = l.split(" ")
                local_role = l[-1][:-1]
                temp[proto_name]["local_role"] = local_role
                match local_role:
                    case "peer":
                        temp[proto_name]["remote_role"] = local_role
                    case "provider":
                        temp[proto_name]["remote_role"] = "customer"
                    case "customer":
                        temp[proto_name]["remote_role"] = "provider"
            elif l.startswith("neighbor"):
                l = l.split(" ")
                temp[proto_name]["remote_ip"] = netaddr.IPAddress(l[1])
                temp[proto_name]["remote_as"] = int(l[-1][:-1])
                is_inter = temp[proto_name]["remote_as"] != my_asn
                temp[proto_name]["is_interior"] = is_inter
            elif l.startswith("source address"):
                l = l.split(" ")
                temp[proto_name]["local_ip"] = netaddr.IPAddress(l[-1][:-1])
            elif l.startswith("interface"):
                self.logger.debug(l)
                temp[proto_name]["interface_name"] = l.split(" ")[1][:-1]
        self.data["check_time"] = time.time()
        self.data["links"] = temp
        self.data["update_time"] = self.data["check_time"]

    def get_all_link_meta(self):
        result = copy.deepcopy(self.data["links"])
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

    def send_msg(self, msg):
        # self.logger.debug(msg)
        msg["schedule_dt"] = time.time()
        match msg["msg_type"]:
            case "http-post":
                sent = self._send_http_post(msg)
            case "dsav":
                self.bird_cmd_buff.put(msg["data"])
                try:
                    self.agent.bird_man.bird_cmd("call_agent")
                    sent = True
                except Exception as e:
                    self.logger.exception(e)
                    sent = False
            case "grpc":
                raise NotImplementedError
            case _:
                raise ValueError(f"unknown msg type {msg['type']}")
        msg["finished_dt"] = time.time()
        # update_metric
        if msg["source_app"] == RPDP_ID:
            match msg["msg_type"]:
                case "dsav":
                    temp = self._update_metric(
                        self.agent.rpdp_app.metric["dsav"], msg)
                    self.agent.rpdp_app.metric["dsav"] = temp
                case _:
                    raise ValueError(f"unknown msg type {msg['type']}")
        else:
            raise ValueError(f"unknown msg source_app {msg['source_app']}")
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

    def add(self, meta_dict):
        self._is_good_meta(meta_dict)
        # self.logger.debug(f"adding {meta_dict}")
        link_type = meta_dict["link_type"]
        link_name = self._get_link_name(meta_dict)
        # self.logger.debug(f"adding {link_name}")
        if link_name in self.data:
            self.logger.warning(f"key {link_name} already exists")
            return
        if not link_type in ["native_bgp", "dsav"]:
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

    def rpdp_links(self, link_map):
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
                if link["link_type"] == "native_bgp":
                    # self.logger.debug(link["protocol_name"])
                    if include_native_bgp:
                        temp.append(link_name)
                else:
                    temp.append(link_name)
        return temp

    def get_all_up_type(self, is_interior, include_native_bgp=False):
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
        if not meta["link_type"] in ["native_bgp", "dsav"]:
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
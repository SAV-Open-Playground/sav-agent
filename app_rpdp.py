# -*-coding:utf-8 -*-
"""
@File    :   app_rpdp.py
@Time    :   2023/07/24
@Author  :   Yuqian Shi
@Version :   0.1

@Desc    :   the app_rpdp.py is responsible for RPDP-SAV rule generation
             In this implementation, the SPA and SPD is encoded into standard BGP Update message
"""

from multiprocessing import Manager

from sav_common import *

class RPDPApp(SavApp):
    """
    a sav app implementation based on reference router (based on bird)
    embeded grpc link
    """
    def __init__(self, agent, name="rpdp_app", logger=None):
        super(RPDPApp, self).__init__(agent, name, logger)
        self.prepared_cmd = Manager().list()
        self.pp_v4_dict = {}

    def get_pp_v4_dict(self):
        # retrun the bird prefix-(AS)path table in RPDPApp (no refreshing)
        return self.pp_v4_dict

    def diff_pp_v4(self):
        """
        return adds and dels,
        which is a list of modification required(tuple of (prefix,path))
        """
        old_ = self.pp_v4_dict
        new_ = self._parse_bird_fib()
        if not "master4" in new_:
            self.logger.warning(
                "no master4 table. Is BIRD ready?")
            return [], []
        new_ = new_["master4"]
        dels = []
        adds = []
        for prefix in new_:
            if prefix not in old_:
                for path in new_[prefix]["as_path"]:
                    adds.append((prefix, path))
            else:
                if new_[prefix] != old_[prefix]:
                    for path in old_[prefix]["as_path"]:
                        if not path in new_[prefix]["as_path"]:
                            dels.append((prefix, path))
                    for path in new_[prefix]["as_path"]:
                        if not path in old_[prefix]["as_path"]:
                            adds.append((prefix, path))
        for prefix in old_:
            if prefix not in new_:
                for path in old_[prefix]["as_path"]:
                    dels.append((prefix, path))
        self.pp_v4_dict = new_
        return adds, dels

    def _parse_birdc_show_table(self, data):
        """
        parse the cmd output of birdc_show_table cmd
        """
        data = data.split("Table")
        while "" in data:
            data.remove("")
        result = {}
        for table in data:
            table_name, table_data = self._parse_bird_table(table)
            result[table_name] = table_data
        return result

    # def _parse_bird_roa(self):
    #     """
    #     """
    #     data = self._bird_cmd(cmd="show route table r4")
    #     if data is None:
    #         return {}

    def _parse_bird_fib(self):
        """
        using birdc show all to get bird fib
        """
        data = self._bird_cmd(cmd="show route all")
        if data is None:
            return {}
        data = data.split("Table")
        while "" in data:
            data.remove("")
        result = {}
        for table in data:
            table_name, table_data = self._parse_bird_table(table)
            result[table_name] = table_data
        return result
    def _build_inter_sav_spa_nlri(self,origin_asn,prefix,route_type=2,flag=1):
        return (route_type,origin_asn,prefix,flag)
    
    def _build_inter_sav_spd(self,sn,origin_router_id,origin_asn,validation_asn,optional_data ,type=2,sub_type=2):
        return (type,sub_type,sn,origin_router_id,origin_asn,validation_asn,optional_data)
    
    def _parse_bird_table(self, table):
        """
        return table_name (string) and parsed_rows (dict)
        only parse the as_path
        """
        # self.logger.debug(table)
        temp = table.split("\n")
        while '' in temp:
            temp.remove('')
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

        for row in rows:
            prefix = row.pop(0)
            if "blackhole" in prefix:
                continue
            prefix = prefix.split(" ")[0]
            # TODO: demo filter
            if str(prefix).startswith("192"):
                prefix = prefix.replace("24-24", "24")
                prefix = netaddr.IPNetwork(prefix)
                temp = {"as_path": []}
                for line in row:
                    if line.startswith("\tBGP.as_path: "):
                        temp["as_path"].append(list(map(
                            int, line.split(": ")[1].split(" "))))
                parsed_rows[prefix] = temp
        return table_name, parsed_rows

    def send_msg(self, msg):
        """
        notify the bird to retrieve the msg from flask server and execute it.
        """
        # self.logger.debug(msg.keys())
        if not isinstance(msg, dict):
            self.logger.error(f"msg is not a dictionary msg is {type(msg)}")
            return
        while len(self.prepared_cmd) > 0:
            self.logger.warn(
                f"last message not finished {self.prepared_cmd}")
            time.sleep(0.01)
        # specialized for bird app, we need to convert the msg to byte array
        msg_byte = self._msg_to_hex_str(msg)
        # self.logger.debug(f"msg_byte({len(msg_byte)}): {msg_byte}")
        self.add_prepared_cmd(msg_byte)
        self._bird_cmd(cmd="call_agent")
        self.logger.info(
            f"SENT MSG ON LINK [{msg['protocol_name']}]:{msg}, time_stamp: [{time.time()}]]")

    def _msg_to_hex_str(self, msg):
        """
        msg is in json format,but bird is difficult to use,
        therefore we transfer the msg to byte array,
        and put that into the json for bird app
        """
        key_types = [("msg_type", str), ("protocol_name", str), ("as4_session", bool), ("sav_nlri", list), ("is_interior", bool)]
        try:
            keys_types_check(msg, key_types)
        except Exception as e:
            self.logger.error(e)
            return None
        hex_str_msg = {"is_native_bgp":0}
        is_as4 = msg["as4_session"]
        hex_str_msg["sav_nlri"] = prefixes_to_hex_str(msg["sav_nlri"])
        hex_str_msg["nlri_len"] = len(decode_csv(hex_str_msg["sav_nlri"]))
        m_t = msg["msg_type"]
        hex_str_msg["protocol_name"] = msg["protocol_name"]
        hex_str_msg["next_hop"] = msg["src"].split(".")
        hex_str_msg["next_hop"] = [
            str(len(hex_str_msg["next_hop"]))] + hex_str_msg["next_hop"]
        hex_str_msg["next_hop"] = ",".join(hex_str_msg["next_hop"])
        hex_str_msg["sav_scope"] = scope_to_hex_str(
            msg["sav_scope"], msg["is_interior"], is_as4)
        hex_str_msg["is_interior"] = 1 if msg["is_interior"] else 0
        if msg["is_interior"]:
            as_path_code = "2"
            hex_str_msg["withdraws"] = "0,0"
            hex_str_msg["sav_origin"] = ",".join(asn2hex(
                msg["sav_origin"], is_as4))
            if m_t == "origin":
                # insert origin for sav
                # using ba_origin, there is no need to convert tot as4
                hex_str_msg["as_path"] = ",".join(
                    [as_path_code, "1", hex_str_msg["sav_origin"]])
                hex_str_msg["as_path_len"] = len(
                    decode_csv(hex_str_msg["as_path"]))
                # insert asn_paths
                return hex_str_msg
            elif m_t == "relay":
                as_number = str(len(msg["sav_path"]))
                temp = path2hex(msg["sav_path"], is_as4)
                hex_str_msg["as_path"] = ",".join(
                    [as_path_code, as_number]+temp)
                hex_str_msg["as_path_len"] = len(
                    decode_csv(hex_str_msg["as_path"]))
                return hex_str_msg
            else:
                self.logger.error(f"unknown msg_type: {m_t}")

        else:
            hex_str_msg["withdraws"] = "0,0"
            hex_str_msg["sav_origin"] = ",".join(
                ipv4_str_to_hex(msg["sav_origin"]))
            return hex_str_msg

    def add_prepared_cmd(self, cmd):
        self.prepared_cmd.append(cmd)

    def get_prepared_cmd(self):
        return self.prepared_cmd.pop(0)

    def _construct_msg(self, link, input_msg, msg_type, is_inter):
        """
        construct a message for apps to use,
        if msg_type is origin, input_msg is the value of sav_scope list of paths
        if msg_type is relay, input_msg a dict include sav_path, sav_nlri, sav_origin, sav_scope
        """
        # self.logger.debug(f"link:{link},input_msg:{input_msg},msg_type:{msg_type},is_inter:{is_inter}")
        try:
            msg = {
                    "src": link["local_ip"],
                    "dst": link["remote_ip"],
                    "msg_type": msg_type,
                    "is_interior": is_inter,
                    "as4_session": link["as4_session"],
                    "protocol_name": link["protocol_name"],
                }
            if "bgp" in link["link_type"]:
                pass
            else:
                msg["dst_id"] = link["remote_id"]
                msg["src_id"] = self.agent.config["grpc_config"]["id"]
            if msg_type == "origin":
                if is_inter:
                    msg["sav_origin"] = link["local_as"]
                    msg["sav_scope"] = input_msg
                else:
                    msg["sav_origin"] = link["router_id"]
                msg["sav_path"] = [msg["sav_origin"]]
                msg["sav_nlri"] = self.agent.get_local_prefixes()
            elif msg_type == "relay":
                msg["sav_origin"] = input_msg["sav_origin"]
                msg["sav_nlri"] = input_msg["sav_nlri"]
                msg["sav_path"] = input_msg["sav_path"]
                msg["sav_scope"] = input_msg["sav_scope"]
            else:
                self.logger.error(f"unknown msg_type:{msg_type}\nmsg:{msg}")
            # filter out empty sav_scope
            temp = []
            for path in msg["sav_scope"]:
                if len(path) > 0:
                    temp.append(path)
            msg["sav_scope"] = temp
            msg["sav_origin"] = str(msg["sav_origin"])
            # if check_agent_agent_msg(msg):
            return msg
        except Exception as e:
            self.logger.error(e)
            self.logger.error("construct msg error")

    def recv_http_msg(self, msg):
        # self.logger.debug("app {} got msg {}".format(self.name, msg))
        try:
            m_t = msg["msg_type"]
            if not m_t in ["bird_bgp_config", "bgp_update"]:
                raise ValueError(f"unknown msg_type: {m_t} received via http")
            if "rpdp" in msg["msg"]["channels"]: 
                link_type = "modified_bgp"
            else:
                link_type = "native_bgp"
            msg["source_app"] = self.name
            msg["source_link"] = msg["msg"]["protocol_name"]
            if m_t == "bgp_update":
                self.put_link_up(msg["source_link"],link_type)
                msg["msg"] = self.preprocess_msg(msg["msg"])
                self.process_rpdp_msg(msg)
            else:
                self.logger.error(msg)
                self.agent.put_msg(msg)
        except Exception as e:
            self.logger.error(e)
    def process_grpc_msg(self, msg):
        link_meta = self.agent.link_man.get_by_name_type(msg["source_link"],"grpc")
        msg["msg"]["interface_name"] = link_meta["interface_name"]
        self.process_rpdp_msg(msg)
    def preprocess_msg(self, msg):
        # as_path is easier to process in string format, so we keep it
        # process routes
        msg["routes"] = decode_csv(input_str=msg["routes"])
        msg["add_routes"] = []
        msg["del_routes"] = []
        for route in msg["routes"]:
            if route[0] == "+":
                msg["add_routes"].append(netaddr.IPNetwork(route[1:]))
            elif route[0] == "-":
                msg["del_routes"].append(netaddr.IPNetwork(route[1:]))
        del msg["routes"]
        # process sav_nlri
        msg["sav_nlri"] = hex_str_to_prefixes(msg["sav_nlri"])

        # process sav_scope
        msg["sav_scope"] = str_to_scope(msg["sav_scope"])

        # process as_path, only used for inter-msgs
        msg["as_path"] = decode_csv(msg["as_path"])
        
        # self.logger.debug(msg)
        return msg
    def process_rpdp_inter(self,msg,link):
        """
        determine whether to relay or terminate the message.
        """
        # self.logger.debug(f"process rpdp inter msg {msg}, link {link}")
        link_meta = link
        scope_data = msg["sav_scope"]
        relay_msg = {
            "sav_nlri": msg["sav_nlri"],
            "sav_origin": msg["sav_origin"]
        }
        new_path = msg["sav_path"]+[link_meta["local_as"]]
        for i in range(len(new_path)-1):
            self.agent.add_sav_link(new_path[i], new_path[i+1])
        self.agent._log_info_for_front(msg=None, log_type="sav_graph")
        relay_scope = {}
        intra_links = self.agent.link_man.get_all_up_type(is_interior=False)
        # if we receive a inter-domain msg via inter-domain link
        if link_meta["is_interior"]:
            for path in scope_data:
                next_as = int(path.pop(0)) # for modified bgp
                if (link_meta["local_as"] != next_as) :
                    self.logger.debug(f"next_as {next_as}({type(next_as)}) local_as {link_meta['local_as']}({type(link_meta['local_as'])})")
                    path.append(next_as)
                    self.logger.error(
                        f"as number mismatch msg:{path} local_as {link_meta['local_as']},next_as {next_as}")
                    return
                if len(path) == 0:
                    self.agent._log_info_for_front(msg, "terminate")

                    # AS_PATH:{msg['sav_path']} at AS {m['local_as']}")
                    for link_name in intra_links:
                        
                        link = self.agent.link_man.data.get(link_name)
                        relay_msg["sav_path"] = msg["sav_path"]
                        relay_msg["sav_scope"] = scope_data
                        relay_msg = self._construct_msg(
                            link, relay_msg, "relay", True)
                        msg1 = relay_msg
                        msg1['sav_nlri'] = list(map(str, msg1['sav_nlri']))
                        self.agent._log_info_for_front(
                            msg, "relay_terminate", link_name)
                        self.logger.debgug("")
                        self.agent._send_msg_to_agent(msg, link)
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
            inter_links = self.agent.link_man.get_by(next_as, True)
            # native_bgp link may included
            inter_links = [i for i in inter_links if i["link_type"]!="native_bgp"]
            relay_msg["sav_scope"] = relay_scope[next_as]
            relay_msg["sav_path"] = msg["sav_path"] + [link_meta["local_as"]]
            for link in inter_links:
                relay_msg["sav_scope"] = relay_scope[next_as]
                relay_msg = self._construct_msg(
                    link, relay_msg, "relay", True)
                self.agent._send_msg_to_agent(relay_msg, link)
                # self.get_app(link["app"]).send_msg(relay_msg)
            if link_meta["is_interior"] and msg["is_interior"]:
                for link_name in intra_links:
                    link = self.agent.link_man.data.get(link_name)
                    relay_msg = self._construct_msg(
                        link, relay_msg, "relay", True)
                    self.agent._send_msg_to_agent(relay_msg, link)
                    # self.get_app(link["app"]).send_msg(relay_msg)
            if len(inter_links) == 0:
                if link_meta["is_interior"]:
                    self.logger.debug(
                        f"unable to find interior link for as:{next_as}, no SAV ?")
    def process_rpdp_msg(self,input_msg):
        """
        process dpdp message, only inter-domain is supported
        regarding the nlri part, the processing is the same
        """
        # self.logger.debug(input_msg)
        link_name = input_msg["source_link"]
        # self.logger.debug(link_name)
        # self.logger.debug((self.agent.link_man.data.keys()))
        link_name = self.agent.link_man.get_by_kv("protocol_name",link_name)
        if len(link_name) != 1:
            self.logger.error(f"link_name error {link_name}")
            return
        link_meta = self.agent.link_man.data.get(link_name[0])
        msg = input_msg["msg"]
        msg["is_interior"] = tell_str_is_interior(msg["sav_origin"])
        prefixes = msg["sav_nlri"]
        temp_list = []
        for prefix in prefixes:
            temp_list.append({"prefix": str(prefix),
                         "neighbor_as": link_meta["remote_as"],
                         "interface": msg["interface_name"],
                         "source_app": self.name,
                         "source_link": link_name,
                         "local_role":link_meta["local_role"]
                         })
        # self.logger.debug(temp_list)
        self.agent.ip_man.add(temp_list)
        # self.logger.debug(list(msg.keys()))
        if msg["is_interior"]:
            # in inter-domain, sav_path is as_path
            if not input_msg["msg_type"] == "grpc_msg":
                msg["sav_path"] = msg["as_path"]
                del msg["as_path"]
                temp = []
                for path in msg["sav_scope"]:
                    temp.append(list(map(int,path)))
                msg["sav_scope"] = temp
            self.process_rpdp_inter(msg, link_meta)
            
        else:
            self.logger.error("INTRA MSG RECEIVED")
            self._process_sav_intra(msg, link_meta)
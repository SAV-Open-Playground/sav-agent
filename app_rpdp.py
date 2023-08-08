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
        grpc_config = self.agent.config.get("grpc_config")
        if grpc_config["enabled"]:
            self._grpc_config(grpc_config)
            
            
    def _grpc_config(self,grpc_config):
        src_ip = grpc_config.get("id")
        link_man = self.agent.link_man
        local_as = grpc_config.get("local_as")
        # add grpc_links
        for grpc_link in grpc_config.get("links"):
            dst = grpc_link["remote_addr"].split(':')
            remote_as = grpc_link["remote_as"]
            dst_ip = dst[0]
            link_dict = self.agent._get_new_link_dict(self.name)
            link_dict["meta"] = {
                "local_ip":src_ip,
                "remote_ip":dst_ip,
                "dst_addr":grpc_link["remote_addr"],
                "is_interior":local_as!=remote_as,
                "local_as":str(local_as),
                "remote_as":str(remote_as),
                "as4_session":True, # True by default
                "protocol_name":"grpc",
            }
            link_dict["status"] = True
            link_man.add(f"grpc_link_{src_ip}_{dst_ip}",link_dict,"grpc")
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
        if not isinstance(msg, dict):
            self.logger.error(f"msg is not a dictionary msg is {type(msg)}")
            return
        while len(self.prepared_cmd) > 0:
            self.logger.warn(
                f"last message not finished {self.prepared_cmd}")
            time.sleep(0.01)
        # specialized for bird app, we need to convert the msg to byte array
        msg_byte = self._msg_to_hex_str(msg)
        self.add_prepared_cmd(msg_byte)
        self._bird_cmd(cmd="call_agent")
        msg1 = msg
        if "sav_nlri" in msg1:
            msg1["sav_nlri"] = list(map(str, msg1["sav_nlri"]))
        if "sav_origin" in msg1:
            while [] in msg1["sav_scope"]:
                msg1["sav_scope"].remove([])
            msg1["sav_scope"] = list(
                map(lambda x: list(map(int, x)), msg1["sav_scope"]))
        self.logger.info(
            f"SENT MSG ON LINK [{msg['protocol_name']}]:{msg}, time_stamp: [{time.time()}]]")

    def _msg_to_hex_str(self, msg):
        """
        msg is in json format,but bird is difficult to use,
        therefore we transfer the msg to byte array,
        and put that into the json for bird app
        """
        for k in ["msg_type", "protocol_name", "as4_session", "sav_nlri", "is_interior"]:
            if k not in msg:
                self.logger.error(
                    f"required key :[{k}] missing in msg:{msg}")
                return None
        hex_str_msg = {}
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
        try:
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
            if check_agent_agent_msg(msg):
                return msg
        except Exception as e:
            self.logger.error(e)
            self.logger.error("construct msg error")

    def recv_msg(self, msg):
        self.logger.debug("app {} got msg {}".format(self.name, msg))
        try:
            key_types = [("msg_type", str)]
            keys_types_check(msg,key_types)
            m_t = msg["msg_type"]
            if m_t in ["bird_bgp_config", "bgp_update"]:
                msg["source_app"] = self.name
                msg["source_link"] = msg["msg"]["protocol_name"]
                
                if "channels" in msg["msg"]:
                # grpc_link is not handled here
                    if "rpdp" in msg["msg"]["channels"]: 
                        link_type = "modified_bgp"
                    else:
                        # self.logger.warning(msg)
                        link_type = "native_bgp"
                # self.logger.debug(msg)
                # self.put_link_up(msg["source_link"])
                self.put_link_up(msg["source_link"],link_type)
                if m_t == "bgp_update":
                    msg["msg"] = self.preprocess_msg(msg["msg"])
                self.agent.put_msg(msg)
            else:
                self.logger.error(f"unknown msg_type: {m_t}\n msg :{msg}")
        except Exception as e:
            self.logger.error(e)

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
        msg["is_native_bgp"] = not (len(msg["sav_nlri"]) > 0)
        # self.logger.debug(msg)
        return msg


# class GrpcApp(SavApp):
#     # in Grpc we can send the json in string format,
#     # so we don't need to convert it to hex string
#     # the sending function is implemented in Sav_agent
        

#     def recv_msg(self, msg, sender_id):
#         self.logger.debug(f"app {self.name} got msg [{msg}]")
#         # add link
#         link_man = self.agent.link_man
#         local_ip = self.agent.config.get('grpc_id')

#         source_link = f"grpc_{local_ip}_{sender_id}"
#         self.logger.debug(source_link)
#         if not link_man.exist(source_link):
#             self.logger.debug(msg)
#             data_dict = self.agent._get_new_link_dict(source_link)
#             data_dict["meta"] = {"local_ip": local_ip, "remote_ip": sender_id}
#             link_man.add(source_link, data_dict)
#             self.put_link_up(source_link)
#         m_t = msg["msg_type"]
#         if m_t in ["origin", "relay"]:
#             temp = {"msg": msg}
#             msg = temp
#             msg["msg_type"] = "bgp_update"
#             msg["source_app"] = self.name
#             msg["source_link"] = source_link
#             self.agent.put_msg(msg)
#         else:
#             self.logger.error(
#                 f"unknown msg_type: {m_t}\n msg :{msg}")

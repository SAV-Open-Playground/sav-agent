# -*-coding:utf-8 -*-
"""
@File    :   app_passport.py
@Time    :   2023/09/04
@Author  :   Yuqian Shi
@Version :   0.1

@Desc    :   implements internal key generation and handling
"""

from multiprocessing import Manager
from sav_common import *
import threading
import pickle
import json
import time
import random
import requests


class PassportApp(SavApp):
    """
    SAV-APP Passport Implementation
    we use flask server for shared key generation
    only perform AS-LEVEL CHECK
    """

    def __init__(self, agent, asn,router_id,name="passport_app", logger=None):
        super(PassportApp, self).__init__( agent,name, logger)
        self.prepared_cmd = Manager().list()
        self.pp_v4_dict = {}
        self.p = 10007
        self.g = 5
        self.private_key = random.randint(1, self.p - 1)
        self.public_key = (self.g ** self.private_key) % self.p
        self.shared_keys = {}
        self.asn = asn
        self.router_id = router_id
    
    def get_pp_v4_dict(self):
        return self.pp_v4_dict
        
    def initialize_share_key(self,target_asn,target_ip):
        self.logger.debug(f"initialize share key with {target_asn} at {target_ip}")
        req = {"asn":self.asn,"router_id":self.router_id,"public_key":self.public_key}
        rep = requests.post(f"http://node_{target_asn}:8888/got_share_key/",json=req)
        self.logger.debug(rep)
        shared_key = (rep['public_key'] ** self.private_key) % self.p
        self.shared_keys[target_asn] = shared_key
        return req
        
    def _get_next_hop(self, target_ip):
        self.pp_v4_dict
        self.logger.debug(self.pp_v4_dict)
    def send_pkt(self, data,target_ip):
        """Warp http over each packet"""
        http_data = {
            "data":data,
            "dst_asn":target_ip,
            "src_asn":self.asn
                     }
    
    def rec_pkt(self, pkt):
        raise NotImplementedError
    def _parse_bird_fib(self):
        """
        using birdc show all to get bird fib
        """
        t0 = time.time()
        # data = self._bird_cmd(cmd="show route all")
        data = self.agent.bird_man.bird_cmd("show route all")
        if data is None:
            return {}
        data = data.split("Table")
        while "" in data:
            data.remove("")
        result = {}
        for table in data:
            table_name, table_data = self._parse_bird_table(table)
            result[table_name] = table_data
        t = time.time()-t0
        if t > TIMEIT_THRESHOLD:
            self.logger.debug(f"TIMEIT {time.time()-t0:.4f} seconds")
        return result

    def diff_pp_v4(self, reset=False):
        """
        return adds and dels,
        which is a list of modification required(tuple of (prefix,path))
        """
        t0 = time.time()
        if reset:
            self.pp_v4_dict = {}
        old_ = self.pp_v4_dict
        new_ = self._parse_bird_fib()
        # self.logger.debug(type(new_))
        # self.logger.debug((new_.keys()))
        if not "master4" in new_:
            self.logger.warning(
                "no master4 table. Is BIRD ready?")
            return [], []
        new_ = new_["master4"]
        dels = []
        adds = []
        # self.logger.debug(new_)
        for prefix, paths in new_.items():
            if prefix not in old_:
                for path in paths["as_path"]:
                    adds.append((prefix, path))
            else:
                if paths != old_[prefix]:
                    for path in old_[prefix]["as_path"]:
                        if not path in paths["as_path"]:
                            dels.append((prefix, path))
                    for path in new_[prefix]["as_path"]:
                        if not path in old_[prefix]["as_path"]:
                            adds.append((prefix, path))
        for prefix in old_:
            if prefix not in new_:
                for path in old_[prefix]["as_path"]:
                    dels.append((prefix, path))
        self.pp_v4_dict = new_
        # self.logger.debug(adds)
        # self.logger.debug(dels)
        t = time.time()-t0
        if t > TIMEIT_THRESHOLD:
            self.logger.debug(f"TIMEIT {time.time()-t0:.4f} seconds")
        return adds, dels

    def _parse_birdc_show_table(self, data):
        """
        parse the cmd output of birdc_show_table cmd
        """
        t0 = time.time()
        data = data.split("Table")
        while "" in data:
            data.remove("")
        result = {}
        for table in data:
            table_name, table_data = self._parse_bird_table(table)
            result[table_name] = table_data
        t = time.time()-t0
        if t > TIMEIT_THRESHOLD:
            self.logger.debug(f"TIMEIT {time.time()-t0:.4f} seconds")
        return result

    # def _parse_bird_roa(self):
    #     """
    #     """
    #     data = self._bird_cmd(cmd="show route table r4")
    #     if data is None:
    #         return {}

    def _build_inter_sav_spa_nlri(self, origin_asn, prefix, route_type=2, flag=1):
        return (route_type, origin_asn, prefix, flag)

    def _build_inter_sav_spd(self, sn, origin_router_id, origin_asn, validation_asn, optional_data, type=2, sub_type=2):
        return (type, sub_type, sn, origin_router_id, origin_asn, validation_asn, optional_data)

    def _parse_bird_table(self, table):
        """
        return table_name (string) and parsed_rows (dict)
        only parse the as_path
        """
        # self.logger.debug(table)
        t0 = time.time()
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
            # if "blackhole" in prefix:
            #     continue
            prefix = prefix.split(" ")[0]
            prefix = prefix.replace("24-24", "24")
            prefix = netaddr.IPNetwork(prefix)
            # if prefix.is_private():
            #     # self.logger.debug(f"private prefix {prefix} ignored")
            #     continue
            temp = {"as_path": []}
            for line in row:
                if line.startswith("\tBGP.as_path: "):
                    temp["as_path"].append(list(map(
                        int, line.split(": ")[1].split(" "))))
            parsed_rows[prefix] = temp
        t = time.time()-t0
        if t > TIMEIT_THRESHOLD:
            self.logger.debug(f"TIMEIT {time.time()-t0:.4f} seconds")
        return table_name, parsed_rows

    def send_msg(self, msg, config, link):
        """send msg to other sav agent"""
        t0 = time.time()
        try:
            link_type = link["link_type"]
            link_name = link["protocol_name"]
            map_data = {}

            if link_name in config["link_map"]:
                link_type = config["link_map"][link_name]["link_type"]
                map_data = config["link_map"][link_name]["link_data"]
            if link_type == "grpc":
                self._send_grpc(msg, link, config["rpdp_id"], map_data)
            elif link_type == "modified_bgp":
                # using reference router
                self._send_modified_bgp(msg)
            elif link_type == "quic":
                a = threading.Thread(target=self._send_quic, args=(
                    msg, link, config["quic_config"], map_data))
      #          a.setDaemon(True)
                a.start()
                a.join()
            elif link_type == "native_bgp":
                # this should not happen
                self.logger.error(link)
                self.logger.error(msg)
            else:
                self.logger.error(f"unhandled msg {msg}")
            t = time.time()-t0
            if t > TIMEIT_THRESHOLD:
                self.logger.debug(f"TIMEIT {time.time()-t0:.4f} seconds")
        except Exception as e:
            self.logger.error(e)
            self.logger.error(f"sending error")

    def _quic_msg_box(self, msg, bgp_meta):
        msg["sav_nlri"] = list(map(prefix2str, msg["sav_nlri"]))
        msg["dummy_link"] = f"savbgp_{bgp_meta['remote_as']}_{bgp_meta['local_as']}"
        return json.dumps(msg)

    def _quic_msg_unbox(self, msg):
        link_meta = self.agent.link_man.get_by_name_type(
            msg["source_link"], "quic")
        msg["msg"]["interface_name"] = link_meta["interface_name"]
        msg["msg"]["as_path"] = msg["msg"]["sav_path"]
        return msg

    async def __quic_send(self, host, configuration, msg, url):
        # self.logger.debug(host)
        # self.logger.debug(url)
        t0 = time.time()
        try:
            async with connect(
                host,
                7777,
                configuration=configuration,
                create_protocol=HttpClient,
                session_ticket_handler=None,
                local_port=0,
                wait_connected=True,
            ) as client:
                client = cast(HttpClient, client)
                ws = await client.websocket(url, subprotocols=["chat", "superchat"])

                await ws.send(msg)
                rep = await ws.recv()
                if not rep == "good":
                    self.logger.debug(rep)
                    self.logger.error("not good")
                await ws.close()
                client._quic.close(error_code=ErrorCode.H3_NO_ERROR)
        except Exception as e:
            self.logger.debug(f"connect {host} failed")
            self.logger.error(type(e))
            self.logger.error(dir(e))
            self.logger.debug(e.name())
            trace = e.with_traceback()
            # self.logger.error(str(e))
            self.logger.error(str(trace))
            self.logger.error(dir(trace))
            self.logger.error()
        t = time.time()-t0
        if t > TIMEIT_THRESHOLD:
            self.logger.debug(f"TIMEIT {time.time()-t0:.4f} seconds")

    # async def __quic_send(self, host, configuration, msg, url):
    #     # self.logger.debug(host)
    #     # self.logger.debug(url)
    #     t0 = time.time()
    #     try:
    #         key = f"quick_{host}"
    #         if key in self.connect_objs:
    #             client = self.connect_objs[key]["client"]
    #             ws = self.connect_objs[key]["ws"]
    #         else:# -*-coding:utf-8 -*-


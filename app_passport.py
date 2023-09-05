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
import hashlib
import hmac


class PassportApp(SavApp):
    """
    SAV-APP Passport Implementation
    we use flask server for shared key generation
    only perform AS-LEVEL CHECK
    Passport will not generate any rule for IPtable,
    it will use HTTP to warp the packet and handle the filtering logic by itself
    """

    def __init__(self, agent, asn,router_id,name="passport_app", logger=None):
        super(PassportApp, self).__init__( agent,name, logger)
        self.prepared_cmd = Manager().list()
        self.pp_v4_dict = {}
        self.p = 10007
        self.g = 5
        self._private_key = random.randint(1, self.p - 1)
        self.public_key = (self.g ** self._private_key) % self.p
        self.initialized_peers = {}
        self.asn = asn
        self.router_id = router_id
        self.test_pkt_id = 0
    
    
    def rec_public_key(self,req):
        asn = req["asn"]
        public_key = req["public_key"]
        if asn in self.initialized_peers:
            return
        shared_key = (public_key ** self._private_key) % self.p
        if not asn in self.initialized_peers:
            self.initialized_peers[asn] = {"shared_key":shared_key,"ip":req["router_id"]}
            self.logger.debug(f"{self.asn}-{asn} shared key is {shared_key}")
    
    
    def get_public_key_dict(self):
        return {"asn":self.asn,"router_id":self.router_id,"public_key":self.public_key}
    
    def initialize_share_key(self,target_asn,target_ip):
        # self.logger.debug(f"initialize share key with {target_asn} at {target_ip}")
        req = self.get_public_key_dict()
        rep = requests.post(f"http://{target_ip}:8888/passport_key_exchange",json=req)
        if rep.status_code != 200:
            self.logger.error(f"get public key failed with {rep.status_code}")
            return None
        else:
            rep = rep.json()
            shared_key = (rep['public_key'] ** self._private_key) % self.p
            self.initialized_peers[target_asn] = {"shared_key":shared_key,"ip":rep["router_id"]}
            self.logger.debug(f"{self.asn}-{target_asn} shared key is {shared_key}")
            return req
    def fib_changed(self):
        # always return empty list,since the passport needs to modify the packet directly    
        return [],[]
    
    def _get_next_hop(self, target_ip):
        """return next_hop asn in int"""
        self.update_pp_v4()
        target_ip = netaddr.IPAddress(target_ip)
        result = None
        for prefix in self.pp_v4_dict:
            if target_ip in prefix:
                if result:
                    if prefix in result[0]:
                        result = (prefix, self.pp_v4_dict[prefix])
                else:
                    result = (prefix, self.pp_v4_dict[prefix])
        result = result[1]["as_path"]
        if len(result) != 1:
            self.logger.error("as_path length is not 1")
            self.logger.debug(result)
            raise ValueError
        result = result[0][0]
        return result
    
    def send_pkt(self,target_ip,msg = None):
        """Warp http over each packet"""
        next_hop_asn = self._get_next_hop(target_ip)
        next_hop_ip = self.initialized_peers[next_hop_asn]["ip"]
        key = self.initialized_peers[next_hop_asn]["shared_key"]
        self.test_pkt_id +=1
        if msg is None:
            msg = f"testing packet_{self.test_pkt_id} from asn: {self.asn}"
        
        data_for_mac = f"{self.router_id}{target_ip}{len(msg)}ipv4{msg[:8]}".encode()
        mac = self.calculate_mac(data_for_mac,key)
        pkt = {
            "data": msg,
            "target_ip": target_ip,
            "origin_ip": self.router_id,
            "dst_ip": next_hop_ip,
            "src_ip":self.router_id, # maybe incorrect,but we don't care
            "src_asn":self.asn,
            "mac":mac
            }
        # self.logger.debug(f"http://{next_hop_ip}:8888/passport_rec_pkt")
        rep = requests.post(f"http://{next_hop_ip}:8888/passport_rec_pkt",json=pkt)
        if not rep.status_code == 200:
            self.logger.error(f"send packet failed with {rep.status_code}")
        # self.logger.debug(f"send packet to {next_hop_ip}")
        
    def calculate_mac(self,data,key):
        key = str(key).encode()
        mac = hmac.new(key,data,hashlib.sha256)
        return str(mac.hexdigest())
    
    def check_mac(self,pkt):
        data_for_mac = f"{pkt['origin_ip']}{pkt['target_ip']}{len(pkt['data'])}ipv4{pkt['data'][:8]}".encode()
        mac = self.calculate_mac(data_for_mac,self.initialized_peers[pkt["src_asn"]]["shared_key"])
        return mac == pkt["mac"]
    
    def rec_pkt(self, pkt):
        if not self.check_mac(pkt):
            self.logger.error("mac check failed")
            return
        dst_ip = pkt["dst_ip"]
        target_ip = pkt["target_ip"]
        if dst_ip == target_ip:
            self.logger.info(f"packet reach target {target_ip}: {pkt['data']}")
            return
        self.send_pkt(target_ip,pkt["data"])
            
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

    def update_pp_v4(self):
        """
        return adds and dels,
        which is a list of modification required(tuple of (prefix,path))
        """
        new_ = self._parse_bird_fib()
        if not "master4" in new_:
            self.logger.warning(
                "no master4 table. Is BIRD ready?")
            return [], []
        new_ = new_["master4"]
        # self.logger.debug(new_)
        self.pp_v4_dict = new_

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

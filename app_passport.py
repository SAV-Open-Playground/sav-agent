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

    def __init__(self, agent, asn, router_id, name="passport_app", logger=None):
        super(PassportApp, self).__init__(agent, name, logger)
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

    def get_public_key_dict(self):
        return {"asn": self.asn, "router_id": self.router_id, "public_key": self.public_key}

    def get_publish_msg(self):
        my_key = self.get_public_key_dict()
        msg = {"data": my_key, "origin": (self.asn, self.router_id)}
        msg["path"] = [msg["origin"]]
        return msg

    def init_key_publish(self):
        my_peers = self.agent.get_peers()
        origin_msg = self.get_publish_msg()
        for peer_asn, peer_ip in my_peers:
            self.logger.debug(f"init_key_publish with {peer_asn}")
            if peer_asn in self.initialized_peers:
                continue
            rep = requests.post(
                f"http://{peer_ip}:8888/passport_key_exchange", json=origin_msg)
            if rep.status_code != 200:
                self.logger.error(
                    f"get public key failed with {rep.status_code}")
                continue
            rep = rep.json()
            shared_key = (rep['public_key'] ** self._private_key) % self.p
            self.initialized_peers[peer_asn] = {
                "shared_key": shared_key, "ip": rep["router_id"]}
            self.logger.debug(f"init_key_publish success with {peer_asn}")

    def get_peers(self):
        self.logger.debug("self.agent.link_man.data")
        return self.agent.link_man.data

    def process_key_publish(self, msg):
        origin_asn, origin_ip = msg["origin"]
        if not origin_asn in self.initialized_peers:
            shared_key = (msg["data"]["public_key"] **
                          self._private_key) % self.p
            self.initialized_peers[origin_asn] = {
                "shared_key": shared_key, "ip": msg["data"]["router_id"]}
        if self.asn in msg["path"]:
            # terminate
            return
        for peer_asn in my_peers:
            if peer_asn in msg["path"]:
                continue
            msg["path"].append((self.asn, self.router_id))
            rep = requests.post(
                f"http://{target_ip}:8888/passport_key_exchange", json=msg)
            if rep.status_code != 200:
                self.logger.error(
                    f"get public key failed with {rep.status_code}")
                continue

    def fib_changed(self):
        # always return empty list,since the passport needs to modify the packet directly
        return [], []

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

    def send_pkt(self, target_ip, msg=None):
        """Warp http over each packet"""
        next_hop_asn = self._get_next_hop(target_ip)
        next_hop_ip = self.initialized_peers[next_hop_asn]["ip"]
        key = self.initialized_peers[next_hop_asn]["shared_key"]
        self.test_pkt_id += 1
        if msg is None:
            msg = f"testing packet_{self.test_pkt_id} from asn: {self.asn}"

        data_for_mac = f"{self.router_id}{target_ip}{len(msg)}ipv4{msg[:8]}".encode(
        )
        mac = self.calculate_mac(data_for_mac, key)
        pkt = {
            "data": msg,
            "target_ip": target_ip,
            "origin_ip": self.router_id,
            "dst_ip": next_hop_ip,
            "src_ip": self.router_id,  # maybe incorrect,but we don't care
            "src_asn": self.asn,
            "mac": mac
        }
        # self.logger.debug(f"http://{next_hop_ip}:8888/passport_rec_pkt")
        rep = requests.post(
            f"http://{next_hop_ip}:8888/passport_rec_pkt", json=pkt)
        if not rep.status_code == 200:
            self.logger.error(f"send packet failed with {rep.status_code}")
        # self.logger.debug(f"send packet to {next_hop_ip}")

    def calculate_mac(self, data, key):
        key = str(key).encode()
        mac = hmac.new(key, data, hashlib.sha256)
        return str(mac.hexdigest())

    def check_mac(self, pkt):
        data_for_mac = f"{pkt['origin_ip']}{pkt['target_ip']}{len(pkt['data'])}ipv4{pkt['data'][:8]}".encode(
        )
        mac = self.calculate_mac(
            data_for_mac, self.initialized_peers[pkt["src_asn"]]["shared_key"])
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
        self.send_pkt(target_ip, pkt["data"])

    def _build_inter_sav_spa_nlri(self, origin_asn, prefix, route_type=2, flag=1):
        return (route_type, origin_asn, prefix, flag)

    def _build_inter_sav_spd(self, sn, origin_router_id, origin_asn, validation_asn, optional_data, type=2, sub_type=2):
        return (type, sub_type, sn, origin_router_id, origin_asn, validation_asn, optional_data)

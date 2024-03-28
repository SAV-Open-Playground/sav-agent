# -*-coding:utf-8 -*-
"""
@File    :   app_passport.py
@Time    :   2023/09/04
@Version :   0.1

@Desc    :   implements internal key generation and handling
"""

import random
import hashlib
import hmac


from common import *
PASSPORT_ID = "passport"


class PassportApp(SavApp):
    """
    SAV-APP Passport Implementation
    we use flask server for shared key generation
    only perform AS-LEVEL CHECK
    Passport will not generate any rule for IPtable,
    it will use HTTP to warp the packet and handle the filtering logic by itself
    """

    def __init__(self, agent, name="passport_app", logger=None):
        super(PassportApp, self).__init__(agent, name, logger)
        self.p = 10007
        self.g = 5
        self._private_key = random.randint(1, self.p - 1)
        self.public_key = (self.g ** self._private_key) % self.p
        self.initialized_peers = {}
        self.test_pkt_id = 0
        self._init_metric()
        self.relay_history = {}

    def _init_metric(self):
        self.metric = {
            "key_exchange": init_protocol_metric(),
            "pkt": init_protocol_metric(),
        }

    def get_public_key_dict(self, source_ip=""):
        return {"asn": self.agent.config['local_as'], "router_id": self.agent.config['router_id'],
                "public_key": self.public_key}

    def update_metric(self, msg, key1, is_send, is_start, start_time=None):
        """
        is_send = True: send
        is_send = False: receive
        is_start = True: start
        is_start = False: end
        """
        t0 = time.time()
        data = self.metric[key1]
        if is_start:
            if data["start"] is None:
                data["start"] = t0
            else:
                if data["start"] > t0:
                    data["start"] = t0
            return t0
        else:
            if start_time is None:
                raise ValueError("start_time is None")
            process_t = t0 - start_time
            if data["end"] is None:
                data["end"] = t0
            else:
                if data["end"] < t0:
                    data["end"] = t0
            if is_send:
                data = data["send"]

            else:
                data = data["recv"]
            data["count"] += 1
            data["time"] += process_t
            data["size"] += len(str(msg))

    def get_publish_msg(self):
        """get standard public key message"""
        my_key = self.get_public_key_dict()
        msg = {"data": my_key, "origin": (
            self.agent.config['local_as'], self.agent.config['router_id'])}
        msg["path"] = [msg["origin"]]
        return msg

    def init_key_publish(self):
        """
        initialize the key exchange process with peers
        """
        origin_msg = self.get_publish_msg()
        for peer_asn, peer_ip in self.get_peers():
            if peer_asn in self.initialized_peers:
                continue
            rep = self._send_to_remote(peer_ip, origin_msg)
            rep = rep.json()
            shared_key = (rep['public_key'] ** self._private_key) % self.p
            self.initialized_peers[peer_asn] = {
                "shared_key": shared_key, "ip": rep["router_id"]}
            self.logger.debug(
                f"initialize key success with {peer_asn} {len(self.initialized_peers.keys())} at {time.time()}")

    def get_peers(self):
        result = []
        # for peer_asn,peer_data in self.initialized_peers.items():
        #     # result[peer_asn] = peer_data["ip"]
        #     result.append((peer_asn,peer_data["ip"]))
        for _, data in self.agent.link_man.get_all_link_meta().items():
            peer_as = data["remote_as"]
            peer_ip = str(data["remote_ip"])
            # if peer_as in result:
            #     if not peer_ip == result[peer_as]:
            #         pass
            #         # self.logger.warning(f"existing {result[peer_as]}, new :{peer_ip}")
            # else:
            #     result[peer_as]=peer_ip
            result.append((peer_as, peer_ip))
        return result

    def _send_to_remote(self, remote_ip, msg, timeout=5, path="passport_key_exchange"):
        """
        will retry until success
        """
        if path == "passport_key_exchange":
            metric_key = "key_exchange"
            start = self.update_metric(msg, metric_key, True, True)
        url = f"http://{remote_ip}:8888/{path}/"
        # msg = get_send_buff_msg(self.app_id, "rpdp-http", {"url":url}, msg,retry_forever=True,response=False)
        # self.agent.send_buff.put(msg)
        retry_count = 0
        while True:
            try:
                rep = requests.post(url, json=msg, timeout=timeout)
                if rep.status_code == 200:
                    return rep
            except Exception as e:
                retry_count += 1
                time.sleep(0.01)
                # self.logger.exception(e)
                self.logger.warning(
                    f"passport send packet to {remote_ip} failed {retry_count}")

    def process_key_publish(self, input_msg):
        # self.logger.debug(input_msg)
        msg = input_msg["msg"]
        # self.logger.debug(msg)
        origin_asn, origin_ip = msg["origin"]
        if origin_asn == self.agent.config['local_as']:
            return
        if not origin_asn in self.initialized_peers:
            shared_key = (msg["data"]["public_key"] **
                          self._private_key) % self.p
            self.initialized_peers[origin_asn] = {
                "shared_key": shared_key, "ip": origin_ip}
            self.logger.debug(
                f"initialize key success with {origin_asn} {len(self.initialized_peers.keys())} at {time.time()} {origin_ip}")
        if [self.agent.config['local_as'], self.agent.config['router_id']] in msg["path"]:
            # terminate if already processed
            return

        relay_scope = {}
        for peer_asn, peer_ip in self.get_peers():
            if [peer_asn, peer_ip] in msg["path"]:
                continue
            relay_scope[peer_asn] = peer_ip

        msg["path"].append([self.agent.config['local_as'],
                           self.agent.config['router_id']])
        for peer_asn, peer_ip in relay_scope.items():
            if not peer_asn in self.relay_history:
                self.relay_history[peer_asn] = {}
            if not origin_asn in self.relay_history[peer_asn]:
                self.relay_history[peer_asn][origin_asn] = None
                # self.logger.debug(f"relaying to {peer_ip}")
                self._send_to_remote(peer_ip, msg)

    def generate_sav_rules(self, *args, **kwargs):
        # always return empty list,since the passport needs to modify the packet directly instead of generating savrules
        self.init_key_publish()
        return {}, set()

    def _get_next_hop(self, target_ip):
        target_ip = netaddr.IPAddress(target_ip)
        result = None
        # TODO is using remote_route correct?
        # self.logger.debug(self.agent.bird_man.bird_fib["remote_route"])
        for prefix, data in self.agent.bird_man.bird_fib["remote_route"].items():
            # self.logger.debug(f"prefix {prefix} data {data}")
            if not target_ip in prefix:
                continue
            if result:
                if prefix in result[0]:
                    result = (prefix, data)
            else:
                result = (prefix, data)
        if result is None:
            self.logger.warning(f"no route to {target_ip}")
            raise ValueError
        result = result[1]["as_path"]
        if len(result) == 0:
            # indicate the target is a directly connected peer
            for link_name, link_meta in self.agent.bird_man.protos["links"].items():
                link_meta = link_meta["meta"]
                self.logger.debug(link_meta)
                self.logger.debug(target_ip)
                if netaddr.IPAddress(link_meta["remote_ip"]) == target_ip:
                    return link_meta["remote_as"]
            raise ValueError("no directly connected peer")
        if len(result) != 1:
            self.logger.error("as_path length is not 1")
            self.logger.debug(result)
            raise ValueError
        result = result[0][0]
        return result

    def send_pkt(self, target_ip, msg=None):
        """Warp http over each packet"""
        # self.logger.debug(f"sending to {target_ip}")
        next_hop_asn = self._get_next_hop(target_ip)
        next_hop_ip = self.initialized_peers[next_hop_asn]["ip"]
        key = self.initialized_peers[next_hop_asn]["shared_key"]
        self.test_pkt_id += 1
        if msg is None:
            msg = f"testing packet_{self.test_pkt_id} from asn: {self.agent.config['local_as']}"
        # self.logger.debug(f"send packet {msg}")
        data_for_mac = f"{self.agent.config['router_id']}{target_ip}{len(msg)}ipv4{msg}".encode(
        )
        mac = self.calculate_mac(data_for_mac, key)
        pkt = {
            "data": msg,
            "target_ip": target_ip,
            "origin_ip": self.agent.config['router_id'],
            "dst_ip": next_hop_ip,
            # maybe incorrect,but we don't care
            "src_ip": self.agent.config['router_id'],
            "src_asn": self.agent.config['local_as'],
            "mac": mac
        }

        # self.logger.debug(f"http://{next_hop_ip}:8888/passport_rec_pkt")
        self.logger.debug(f"sending packet to {target_ip}({next_hop_ip})")
        self._send_to_remote(next_hop_ip, pkt, path="passport_rec_pkt")

    def calculate_mac(self, data, key):
        key = str(key).encode()
        mac = hmac.new(key, data, hashlib.sha256)
        return str(mac.hexdigest())

    def check_mac(self, pkt):
        data_for_mac = f"{pkt['origin_ip']}{pkt['target_ip']}{len(pkt['data'])}ipv4{pkt['data']}".encode(
        )
        mac = self.calculate_mac(
            data_for_mac, self.initialized_peers[pkt["src_asn"]]["shared_key"])
        return mac == pkt["mac"]

    def reset_metric(self):
        self._init_metric()

    def rec_pkt(self, msg):
        pkt = msg["msg"]
        if not self.check_mac(pkt):
            self.logger.error("mac check failed")
            return
        dst_ip = pkt["dst_ip"]
        target_ip = pkt["target_ip"]
        if dst_ip == target_ip:
            # self.logger.info(f"packet reach target {target_ip}: {pkt['data']}")
            return
        # self.logger.debug(target_ip)
        self.send_pkt(target_ip, pkt["data"])

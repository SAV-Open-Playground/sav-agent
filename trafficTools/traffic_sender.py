# -*- coding: utf-8 -*-
"""
-------------------------------------------------
   File Name：     traffic_sender.py
   Description :
   date：          2023/6/20
-------------------------------------------------
   Change Activity:
                   2023/6/20:
-------------------------------------------------
"""
import argparse
from scapy.all import *
from scapy.layers.inet import IP, ICMP


class TrafficSender:
    @staticmethod
    def send(dst, src=None, iface=None, trans_num=10):
        success_count, fail_count = 0, 0
        for i in range(trans_num):
            if src is None:
                packet = Ether() / IP(dst=dst) / ICMP()
            else:
                packet = Ether() / IP(src=src, dst=dst) / ICMP()
            reply = srp1(packet, timeout=1, iface=iface, verbose=0)
            if reply and reply.haslayer(ICMP) and reply[ICMP].type == 0:
                success_count += 1
            if reply is None:
                fail_count += 1
        return {"send_count": trans_num, "success_count": success_count, "fail_count": fail_count}


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument('--dst')
    parser.add_argument('--src', default=None)
    parser.add_argument('--iface', default=None)
    parser.add_argument('--trans_num', type=int, default=10)
    args = parser.parse_args()

    dst, src, iface, trans_num = args.dst, args.src, args.iface, args.trans_num
    count = TrafficSender.send(dst=dst, src=src, iface=iface, trans_num=trans_num)
    print(count)
    
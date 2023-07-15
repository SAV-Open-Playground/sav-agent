# -*- coding: utf-8 -*-
"""
-------------------------------------------------
   File Name：     traffiic_receiver
   Description :
   date：          2023/6/20
-------------------------------------------------
   Change Activity:
                   2023/6/20:
-------------------------------------------------
"""
import argparse
from scapy.all import *
from scapy.layers.inet import IP, ICMP, TCP

parser = argparse.ArgumentParser()
parser.add_argument('--dst')
parser.add_argument('--src', default=None)
args = parser.parse_args()
dst, src = args.dst, args.src

timeout = 10


def packet_callback(packet):
    if packet.haslayer(IP):
        ip_packet = packet.getlayer(IP)
        if ip_packet.src == src and ip_packet.dst == dst:
            print("Get sent packet: ", packet.summary())


# sniff(filter=f"src host {src} and dst host {dst}", prn=packet_callback, timeout=10)

sniff(filter=f"src host {src} and dst host {dst}", prn=packet_callback)
print(2)
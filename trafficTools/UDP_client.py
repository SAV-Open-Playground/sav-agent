# -*- coding: utf-8 -*-
"""
-------------------------------------------------
   File Name：     UDP_client
   Description :
   Author :       ustb_
   date：          2023/7/13
-------------------------------------------------
   Change Activity:
                   2023/7/13:
-------------------------------------------------
"""
import socket
import argparse
from scapy.all import *
from scapy.layers.inet import IP, UDP

parser = argparse.ArgumentParser()
parser.add_argument('--dst')
parser.add_argument('--src')
parser.add_argument('--iface')
parser.add_argument('--trans_num', type=int, default=10)
args = parser.parse_args()
dst, src, iface, trans_num = args.dst, args.src, args.iface, args.trans_num


# udp=socket.socket(socket.AF_INET,socket.SOCK_DGRAM)
# udp = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_RAW)
# interface = iface
# udp.setsockopt(socket.SOL_SOCKET, 25, str(interface + '\0').encode('utf-8'))
for index in range(1, trans_num+1):
    data = "udp_packet_" + str(index)
    p = Ether() / IP(src=src, dst=dst) / UDP(sport=RandShort(), dport=12345) / Raw(data.encode("utf-8"))
    sendp(p, iface=iface, verbose=True)
    #send(p,iface=iface)
   #  udp.sendto(p,(dst,12345))
    
    
#udp.close()

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
import time

from scapy.all import *
from scapy.layers.inet import IP, ICMP


class TrafficSender:
    @staticmethod
    def send(dst, src=None, iface=None, trans_num=10):
        # 目标IP地址
        # 统计成功到达目标的数
        success_count, fail_count = 0, 0
        for i in range(trans_num):  # 发送10个IP包
            # 构建IP数据包
            if src is None:
                packet = IP(dst=dst) / ICMP()
            else:
                packet = IP(src=src, dst=dst) / ICMP()
            # 发送数据包并等待响应
            reply = sr1(packet, timeout=2, verbose=0)
            # 检查是否收到响应并统计成功数量
            if reply and reply.haslayer(ICMP) and reply[ICMP].type == 0:
                success_count += 1
            if reply is None:
                fail_count += 1
        # 打印成功到达目标的数量
        return {"send_count": trans_num, "success_count": success_count, "fail_count": fail_count}


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument('--dst')
    parser.add_argument('--src', default=None)
    parser.add_argument('--trans_num', type=int, default=10)
    args = parser.parse_args()

    dst, src, trans_num = args.dst, args.src, args.trans_num
    count = TrafficSender.send(dst=dst, src=src, trans_num=trans_num)
    print(count)
    
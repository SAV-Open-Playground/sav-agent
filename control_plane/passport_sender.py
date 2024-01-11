# -*-coding:utf-8 -*-
#!/usr/bin/python3
# -*-coding:utf-8 -*-
"""
@File    :   passport_sender.py
@Time    :   2023/09/12
@Version :   0.1
@Desc    :   The passport_sender.py 
"""


import requests
import time
import sys


def send_pkts(target_ip, pkt_num, kbytes_of_data):
    # data = f"testing_msg at {time.time()}"
    bytes_of_data = 1024*kbytes_of_data
    data = ""
    data += 'a'*(bytes_of_data-len(data))
    json_data = {"target_ip": target_ip,
                 "data": data}
    s = requests.Session()

    for i in range(pkt_num):
        rep = s.post(
            f"http://localhost:8888/passport_send_pkt/", json=json_data, timeout=30)
        if not rep.status_code == 200:
            print(f"send packet failed with {rep.status_code}")
    s.close()

if __name__ == "__main__":
    pkt_num = int(sys.argv[1])
    target_ip = sys.argv[2]
    pkt_bytes = int(sys.argv[3])
    start = time.time()
    send_pkts(target_ip,pkt_num, pkt_bytes)
    print(
        f"total time {time.time() - start} , pkt num {pkt_num}")

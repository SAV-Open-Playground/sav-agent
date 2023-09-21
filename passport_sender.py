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
import threading
import sys


def send_one_pkt(target_ip, pkt_num):
    json_data = {"target_ip": target_ip,
                 "data": f"testing_msg at {time.time()}{'A'*500}"}
    s = requests.Session()
    for i in range(pkt_num):
        rep = s.post(
            f"http://localhost:8888/passport_send_pkt/", json=json_data, timeout=5)
        if not rep.status_code == 200:
            print(f"send packet failed with {rep.status_code}")


if __name__ == "__main__":
    # print(11)
    pkt_num = int(sys.argv[1])
    thread_num = int(sys.argv[2])
    target_ip = sys.argv[3]
    thread_pool = []
    # send_one_pkt(target_ip, pkt_num)
    for _ in range(thread_num):
        t = threading.Thread(target=send_one_pkt, args=(
            target_ip, pkt_num,))
        t.daemon = True
        thread_pool.append(t)
    start = time.time()
    for t in thread_pool:
        t.start()

    while len(thread_pool) > 0:
        # time.sleep(0.1)
        temp = []
        for t in thread_pool:
            if t.is_alive():
                temp.append(t)
        thread_pool = temp
        # print(f"thread pool size {len(thread_pool)}")
    print(
        f"total time {time.time() - start} , pkt num {pkt_num}, thread num {thread_num}")

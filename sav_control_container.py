#!/usr/bin/python3
# -*-coding:utf-8 -*-
"""
@File    :   sav_control_container.py
@Time    :   2023/09/14
@Version :   0.1
@Desc    :   The sav_control_container.py is responsible for the container 
status and metric report during the emulation process. 
it should be run as main process inside the container.
"""

import time
import os
import json
import subprocess
from datetime import datetime
import requests
from common.logger import get_logger

class Bot:
    def __init__(self):
        self.data_path = r"/root/savop"
        self.signal_path = f"{self.data_path}/signal.json"
        self.sa_config_path = f"{self.data_path}/SavAgent_config.json"
        self.exec_results_path = f"{self.data_path}/logs/exec_results.json"
        self.last_signal = {}
        self.logger = get_logger("sav_control_container")
        self.is_monitor = False
        self.monitor_results = {}
        self.exec_result = {}
        self.stable_threshold = 30
        self.last_check_dt = 0
        self._system_check()

    def _system_check(self):
        """
        ensure the system is ready to run the emulation
        """
        cmd = "sysctl -w "
        # remove rp_filter
        cmds = ["net.ipv4.conf.all.rp_filter=0",
                "net.ipv4.conf.default.rp_filter=0"]
        # set ip forward
        cmds += ["net.ipv4.ip_forward=1", "net.ipv6.conf.all.forwarding=1"]
        # fast closing tcp connection
        cmds += ["net.ipv4.tcp_fin_timeout=1", "net.ipv4.tcp_tw_reuse=1"]

        # increase max open files
        cmds += ["fs.file-max=1000000"]
        # increase max tcp connection

        cmds += ["net.ipv4.tcp_max_syn_backlog=1000000",
                 "net.core.somaxconn=1000000",
                 "net.ipv4.tcp_max_tw_buckets=1000000",
                 "net.ipv4.tcp_max_orphans=1000000"
                 "net.ipv4.tcp_syncookies=1"
                 ]
        for c in cmds:
            try:
                self._run_cmd(cmd+c)
            except Exception as e:
                pass

    def _run_cmd(self, cmd, timeout=60):
        try:
            result = subprocess.run(cmd, shell=True, capture_output=True, encoding='utf-8', timeout=timeout)
        except subprocess.TimeoutExpired:
            return 255
        return result.returncode

    def _http_request_executor(self, url_str, log=True):
        url = f"http://localhost:8888{url_str}"
        if log:
            self.logger.debug(url)
        rep = requests.get(url, timeout=30)
        if rep.status_code != 200:
            self.logger.error(f"request {url} failed")
            return rep
        return rep.text

    def _get_current_datetime_str(self):
        return datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    def check_signal_file(self):
        # base on signal.json and sav_agent_config to predict the next router action
        # execution action:start, stop, keep

        signal = self._read_json(self.signal_path)
        self.stable_threshold = signal["stable_threshold"]
        if signal == {}:
            # initial state ,stop
            return "stop"
        if signal == self.last_signal:
            return "keep"
        local_as = self._read_json(self.sa_config_path)["local_as"]
        command = signal["command"]
        if not command in ["start", "stop"]:
            raise ValueError("unknown command")
        # self.is_monitor = (local_as in signal["command_scope"])
        self.is_monitor = True
        if not self.is_monitor:
            return "keep"
        last_cmd = self.last_signal.get("command", "")
        self.logger.debug(f"last_cmd:{last_cmd} => command:{command}")
        self.last_signal = signal
        return command

    def modify_sav_config_file(self):
        """modify the configuration file for future testing of different sav protocols"""
        pass

    def update_metric(self):
        """
        wait until the fib is stable for the first time
        return None if not stable or error"""
        try:
            ret = self._http_request_executor("/metric/", False)

            ret = json.loads(ret)["agent"]
            if ret["initial_fib_stable"]:
                initial_stable_time = ret["initial_fib_stable_dt"] - ret["first_dt"]
                return initial_stable_time
        except Exception as e:
            self.logger.exception(e)
        return None

    def _wait_for_fib_first_stable(self, check_interval=5):
        """
        wait until the fib is stable for the first time
        write the stable time to the exec_result
        """
        while True:
            time.sleep(check_interval)
            try:
                ret = self._http_request_executor("/metric/", False)
                ret = json.loads(ret)["agent"]
                if ret["initial_fib_stable"]:
                    initial_stable_time = ret["initial_fib_stable_dt"] - ret["first_dt"]
                    self.exec_result.update({"initial_stable_time": initial_stable_time})
                    self._write_json(self.exec_results_path, self.exec_result)
            except Exception as e:
                self.logger.exception(e)

    def _write_json(self, file_path, data):
        json.dump(data, open(file_path, "w", encoding="utf-8"), indent=2)

    def _read_json(self, file_path):
        if not os.path.exists(file_path):
            self.logger.warning(f"{file_path} not exists, return default value")
            return {}
        return json.load(open(file_path, "r", encoding="utf-8"))

    def stop_server(self, action):
        signal = self._read_json(self.signal_path)
        exec_result = self.exec_result
        exec_result.update({"command": f'{signal["command"]}_{time.time()}',
                            "execute_start_time": f"{self._get_current_datetime_str()}",
                            "cmd_exe_dt": time.time(),
                            "action": action})
        result = self._run_cmd("iptables -F SAVAGENT")
        result = self._run_cmd(
            "bash /root/savop/router_kill_and_start.sh stop")
        if result == 0:
            exec_result.update({"execute_end_time": f"{self._get_current_datetime_str()}",
                                "execute_result": "ok"})
        else:
            exec_result.update({"execute_end_time": f"{self._get_current_datetime_str()}",
                                "execute_result": "fail"})
        self.exec_result = exec_result
        self._write_json(self.exec_results_path, exec_result)

    def start_server(self, action):
        signal = self._read_json(self.signal_path)
        # exec_result = self._read_json(self.exec_results_path)\
        exec_result = {}
        # dynamically modify the configuration file of the SAV agent
        sav_agent_config = self._read_json(self.sa_config_path)
        source = signal["source"]
        if source in ["RPDP"]:
            sav_agent_config["enabled_sav_app"] = source
        elif source == "fpurpf_app":
            sav_agent_config["apps"] = ["RPDP", "FP-uRPF"]
        elif source == "strict_urpf_app":
            sav_agent_config["apps"] = ["Strict-uRPF"]
        elif source == "loose_urpf_app":
            sav_agent_config["apps"] = ["Loose-uRPF"]
        elif source == "EFP-uRPF-Algorithm-A_app":
            sav_agent_config["apps"] = ["RPDP", "EFP-uRPF-A"]
        elif source == "EFP-uRPF-Algorithm-B_app":
            sav_agent_config["apps"] = ["RPDP", "EFP-uRPF-B"]
        elif source == "Passport_app":
            sav_agent_config["apps"] = ["Passport"]
        elif source == "BAR_app":
            sav_agent_config["apps"] = ["BAR"]
        elif source is None:
            sav_agent_config["apps"] = []
        else:
            self.logger.error(f"unknown source {source}")
            raise ValueError("unknown source")
        self._write_json(self.sa_config_path, sav_agent_config)
        exec_result.update({"command": f'{signal["command"]}_{time.time()}',
                            "execute_start_time": f"{self._get_current_datetime_str()}",
                            "cmd_exe_dt": time.time(),
                            "action": action})
        result = os.system("bash /root/savop/router_kill_and_start.sh start")
        if result == 0:
            exec_result.update({"execute_end_time": f"{self._get_current_datetime_str()}",
                                "execute_result": "ok",
                                "stable_down_count": 10
                                })
        else:
            exec_result.update({"execute_end_time": f"{self._get_current_datetime_str()}",
                                "execute_result": "fail"})
        self.exec_result = exec_result
        self._write_json(self.exec_results_path, exec_result)

    def run(self):
        # continuously monitor the status of the configuration file in a loop
        while True:
            time.sleep(0.1)
            try:
                action = self.check_signal_file()
                # self.logger.debug(f"action: {action}")
                if action == "start":
                    self.start_server(action=action)
                elif action == "stop":
                    self.stop_server(action=action)
                elif action == "keep":
                    if self.is_monitor:
                        if self.last_cmd == "start":
                            self._wait_for_fib_first_stable()
                else:
                    self.logger.error(f"unknown action {action}")
            except Exception as e:
                continue


if __name__ == "__main__":
    a = Bot()
    a.run()

# -*- coding: utf-8 -*-
"""
-------------------------------------------------
   File Name：     tools
   Description :
   date：          2023/7/3
-------------------------------------------------
   Change Activity:
                   2023/7/3:
-------------------------------------------------
"""
import subprocess


def command_executor(command):
    return subprocess.run(command, shell=True, capture_output=True, encoding='utf-8')


def get_host_interface_list():
    """
    return a list of 'clean' interface names
    """
    command = "ip link|grep -v 'link' | grep -v -E 'docker0|lo' | awk -F: '{ print $2 }' | sed 's/ //g'"
    command_result = command_executor(command=command)
    std_out = command_result.stdout
    # self.logger.debug(command_result)
    result = std_out.split("\n")[:-1]
    result = list(map(lambda x: x.split('@')[0], result))
    return [i for i in result if len(i) != 0]
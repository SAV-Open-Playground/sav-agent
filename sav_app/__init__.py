# -*- coding: utf-8 -*-
"""
-------------------------------------------------
   File Name:     __init__.py
   Description :
   Author :       MichaelYoung
   date:          2024/1/2
-------------------------------------------------
   Change Activity:
                   2024/1/2:
-------------------------------------------------
"""
# imort your sav_app here and include your string_id here
# from .app_bar import BarApp
# from .app_urpf import UrpfApp
from .app_rpdp import RPDPApp, RPDP_ID
from .app_urpf import UrpfApp, STRICT_URPF_ID, LOOSE_URPF_ID
ALL_SAV_MECHANISM_IDs = [STRICT_URPF_ID, LOOSE_URPF_ID, RPDP_ID]


def sav_app_init(agent, logger):
    """
    init sav_app instances here,
    return a dict of instances,key is string_id,value is instance
    """
    try:
        ret = {}
        ret[RPDP_ID] = RPDPApp(
            agent, logger=logger, name=RPDP_ID)
        ret[STRICT_URPF_ID] = UrpfApp(
            agent, logger=logger, name=STRICT_URPF_ID, mode="strict")
        ret[LOOSE_URPF_ID] = UrpfApp(
            agent, logger=logger, name=LOOSE_URPF_ID, mode="loose")
    except Exception as e:
        logger.exception(e)
        ret = {}
    return ret

# -*- coding: utf-8 -*-
"""
-------------------------------------------------
   File Name:     __init__.py
   Description :
   Author :       MichaelYoung
   date:          2024/1/2
"""
# imort your sav_app here and include your string_id here
from .app_rpdp import RPDPApp, RPDP_ID
from .app_urpf import UrpfApp, STRICT_URPF_ID, LOOSE_URPF_ID
from .app_fp_urpf import FpUrpfApp, FP_URPF_ID
from .app_efp_urpf import EfpUrpfApp, EFP_URPF_A_ID, EFP_URPF_B_ID
from .app_efp_urpf import EFP_URPF_A_ASPA_ID, EFP_URPF_B_ASPA_ID
from .app_efp_urpf import EFP_URPF_A_ROA_ID, EFP_URPF_B_ROA_ID
from .app_efp_urpf import EFP_URPF_A_ROA_ASPA_ID, EFP_URPF_B_ROA_ASPA_ID
from .app_bar import BarApp, BAR_ID
from .app_passport import PassportApp, PASSPORT_ID

ALL_SAV_MECHANISM_IDs = [STRICT_URPF_ID, LOOSE_URPF_ID, RPDP_ID, EFP_URPF_B_ROA_ASPA_ID, EFP_URPF_A_ROA_ASPA_ID,
                         EFP_URPF_A_ASPA_ID, EFP_URPF_B_ASPA_ID, EFP_URPF_B_ROA_ID, EFP_URPF_A_ROA_ID, EFP_URPF_A_ID, EFP_URPF_B_ID]


def sav_app_init(agent, logger):
    """
    init sav_app instances here,
    return a dict of instances,key is string_id,value is instance
    """
    try:
        ret = {}
        ret[RPDP_ID] = RPDPApp(agent, RPDP_ID, logger)

        ret[STRICT_URPF_ID] = UrpfApp(agent, STRICT_URPF_ID, "strict", logger)
        ret[LOOSE_URPF_ID] = UrpfApp(agent, LOOSE_URPF_ID, "loose", logger)

        ret[FP_URPF_ID] = FpUrpfApp(agent, FP_URPF_ID, logger)

        ret[EFP_URPF_A_ID] = EfpUrpfApp(agent, EFP_URPF_A_ID, logger)
        ret[EFP_URPF_B_ID] = EfpUrpfApp(agent, EFP_URPF_B_ID, logger)
        ret[EFP_URPF_A_ROA_ID] = EfpUrpfApp(agent, EFP_URPF_A_ROA_ID, logger)
        ret[EFP_URPF_B_ROA_ID] = EfpUrpfApp(agent, EFP_URPF_B_ROA_ID, logger)
        ret[EFP_URPF_A_ASPA_ID] = EfpUrpfApp(agent, EFP_URPF_A_ASPA_ID, logger)
        ret[EFP_URPF_B_ASPA_ID] = EfpUrpfApp(agent, EFP_URPF_B_ASPA_ID, logger)
        ret[EFP_URPF_A_ROA_ASPA_ID] = EfpUrpfApp(
            agent, EFP_URPF_A_ROA_ASPA_ID, logger)
        ret[EFP_URPF_B_ROA_ASPA_ID] = EfpUrpfApp(
            agent, EFP_URPF_B_ROA_ASPA_ID, logger)

        ret[BAR_ID] = BarApp(agent, BAR_ID, logger)

        ret[PASSPORT_ID] = PassportApp(agent, PASSPORT_ID, logger)

    except Exception as e:
        logger.exception(e)
        ret = {}
    return ret

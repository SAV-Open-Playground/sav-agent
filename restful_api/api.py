# -*- coding: utf-8 -*-
"""
-------------------------------------------------
   File Name:     api
   Description :
   Author :       MichaelYoung
   date:          2024/1/3
-------------------------------------------------
   Change Activity:
                   2024/1/3:
-------------------------------------------------
"""
import json
import pickle
import time
import copy

from flask import request, Blueprint
from common import RPDP_OVER_BGP, RPDP_OVER_HTTP, TIMEIT_THRESHOLD, json_w
from common.main_logger import LOGGER
from control_plane import SA
from data_plane.data_plane_enable import interceptor
from sav_app import RPDP_ID

api_blueprint = Blueprint("api", __name__)


@api_blueprint.route("/bird_bgp_upload/", methods=["POST", "GET"])
def index():
    """
    the entrypoint for reference_router
    """
    t0 = time.time()
    rep = {}
    try:
        msg = json.loads(request.data)
    except Exception as err:
        LOGGER.exception(err)
        LOGGER.error(err)
        return {"code": "5001", "message": "Invalid Json String", "data": str(request.data)}
    try:
        required_keys = ["msg_type", "msg"]
        for key in required_keys:
            if key not in msg:
                LOGGER.warning(f"{key} not found in {msg.keys()}")
                return {"code": "5002", "message": f"{key} not found!"}
        m_t = msg["msg_type"]
        if m_t == "request_cmd":
            rep = {"code": "0000", "message": "success"}
            try:
                # LOGGER.debug(f"bird try to get cmd")
                cmd = SA.link_man.bird_cmd_buff.get()
                SA.link_man.bird_cmd_buff.task_done()
                # LOGGER.debug(f"bird got cmd {cmd}")
                return {"code": "2000", "data": cmd, "message": "success"}
            except IndexError as err:
                SA.logger.warning(f"bird try to get cmd but no cmd in queue")
                pass
            t = time.time()-t0
            if t > TIMEIT_THRESHOLD:
                LOGGER.warning(f"TIMEIT {time.time()-t0:.4f} seconds")
            return rep
        msg["source_app"] = RPDP_ID
        if m_t == "link_state_change":
            msg["source_link"] = msg["protocol_name"]
        else:
            msg["source_link"] = msg["msg"]["protocol_name"]
            if not m_t == "link_state_change":
                msg['link_type'] = "bgp"
                if RPDP_ID in msg["msg"]["channels"]:
                    msg['link_type'] = RPDP_OVER_BGP
        msg["pkt_rec_dt"] = t0
        SA.put_msg(msg)
        rep = {"code": "0000", "message": "success"}
    except Exception as err:
        LOGGER.exception(err)
        LOGGER.error(type(err))
        LOGGER.error(msg)
        LOGGER.error(err)
        rep = {"code": "5004", "message": str(err), "data": str(request.data)}
    t = time.time()-t0
    if t > TIMEIT_THRESHOLD:
        LOGGER.warning(f"TIMEIT {time.time()-t0:.4f} seconds")
    return rep


@api_blueprint.route("/put_bgp_update/", methods=["POST", "GET"])
def put_bgp_update():
    """
    put a bpg update message
    """
    LOGGER.debug("enter put_bgp_update")
    t0 = time.time()
    try:
        msg = {"msg": {"protocol_name": "eth_r3"},
               "msg_type": "bgp_update",
               "source_link": "eth_r3"}
        msg["source_app"] = RPDP_ID
        msg["pkt_rec_dt"] = t0
        SA.put_msg(msg)
        rep = {"code": "0000", "message": "success"}
    except Exception as err:
        LOGGER.exception(err)
        LOGGER.error(type(err))
        LOGGER.error(msg)
        LOGGER.error(err)
        rep = {"code": "5004", "message": str(err), "data": str(request.data)}
    t = time.time()-t0
    if t > TIMEIT_THRESHOLD:
        LOGGER.warning(f"TIMEIT {time.time()-t0:.4f} seconds")
    return rep

# @api_blueprint.route('/update_config/', methods=["POST"])
# def update_config():
#     LOGGER.debug("enter update_config")
#     msg = "updated"
#     try:
#         return _update_config()
#     except Exception as err:
#         LOGGER.exception(err)
#         LOGGER.error(err)
#         msg = str(err)
#     return {"code": "0000", "message": msg}


@api_blueprint.route('/metric/', methods=["POST", "GET"])
def metric():
    try:
        SA.data["metric"]["is_processing"] = SA._in_msgs.unfinished_tasks > 0 or SA.link_man._send_buff.unfinished_tasks > 0
        rep = {"agent": SA.data["metric"]}
        if SA.rpdp_app:
            rep[SA.rpdp_app.app_id] = SA.rpdp_app.metric
        if SA.passport_app:
            rep[SA.passport_app.app_id] = SA.passport_app.metric
        return json.dumps(rep, indent=2)
    except Exception as e:
        LOGGER.exception(e)
        return "{}"


@api_blueprint.route('/sav_table/', methods=["POST", "GET"])
def sav_table():
    rep = copy.deepcopy(SA.data["sav_table"])
    return str(rep)


@api_blueprint.route('/save_sav_table/', methods=["POST", "GET"])
def save_sav_table():
    p = "/root/savop/logs/sav_table.json"
    ret = {}
    for app_id in SA.data["apps"]:
        ret[app_id] = list(SA.get_sav_rules_by_app(
            app_id, ip_version=None).keys())
    json_w(p, ret)
    return p


@api_blueprint.route('/savop_quic/', methods=["POST"])
def savop_quic():
    LOGGER.debug("enter savop_quic")
    t0 = time.time()
    if SA.config["quic_config"]["server_enabled"]:
        msg = json.loads(request.data.decode())
        msg = {
            "msg": msg,
            "source_app": SA.rpdp_app.app_id,
            "link_type": "quic",
            "msg_type": "quic_msg",
            "source_link": msg["dummy_link"],
            "pkt_rec_dt": t0
        }
        try:
            SA.put_msg(msg)
        except Exception as err:
            LOGGER.error(err)
        return {"code": "0000", "message": "msg received"}
    else:
        LOGGER.warning(f"quic got unexpected msg:{request.data.decode()}")
        return {"code": "5004", "message": "quic server disabled"}


@api_blueprint.route('/reset_metric/', methods=["POST", "GET"])
def reset_metric():
    LOGGER.debug("enter reset_metric")
    SA.data["msg_count"] = 0
    if SA.rpdp_app:
        SA.rpdp_app.reset_metric()
    if SA.passport_app:
        SA.passport_app.reset_metric()
    LOGGER.debug(F"PERF-TEST: TEST BEGIN at {time.time()}")
    return {"code": "0000", "message": "reset received"}


@api_blueprint.route('/long_nlri_test/', methods=["POST", "GET"])
def long_nlri_test():
    LOGGER.debug(F"enter long_nlri_test at {time.time()}")
    try:
        bgp_sample = {"as_path": "2,1,0,0,255,222",
                      "as_path_len": 6,
                      "is_interior": 1,
                      "next_hop": "4,10,0,1,1",
                      #   "nlri_len": 4, "protocol_name": "savbgp_65502_65501",
                      "bgp_nlri": "24,23,24,3",
                      "withdraws": "0,0",
                      "is_native_bgp": 1}
        for i in range(1, 100):
            for j in range(1, 255):
                bgp_sample["sav_nlri"] += f"24,1,2,{i+1},{j},"
                bgp_sample["nlri_len"] += 4
    except Exception as e:
        LOGGER.debug(e)
    return {"code": "0000", "message": "reset received"}
    # the returned value is not used by client


@api_blueprint.route('/passport_key_exchange/', methods=['GET', 'POST'])
def passport_key_exchange():
    if SA.passport_app is None:
        LOGGER.warning("passport app not detected")
        return None
    msg = {
        "msg_type": "passport_key_exchange",
        "msg": request.json,
        "source_app": "passport_app",
        "source_link": "",
        "pkt_rec_dt": time.time()
    }
    SA.put_msg(msg)
    return SA.passport_app.get_public_key_dict()


@api_blueprint.route('/passport_send_pkt/', methods=['GET', 'POST'])
def passport_send_pkt():
    LOGGER.debug("enter passport_send_pkt")
    if SA.passport_app is None:
        LOGGER.error("passport app not detected")
        return {}
    msg = {
        "msg_type": "passport_send_pkt",
        "msg": request.json,
        "source_app": "passport_app",
        "source_link": "",
        "pkt_rec_dt": time.time()
    }
    # LOGGER.debug(msg)
    SA.put_msg(msg)
    # LOGGER.debug("good")
    return "received"


@api_blueprint.route('/passport_rec_pkt/', methods=['GET', 'POST'])
def passport_rec_pkt():
    LOGGER.debug("enter passport_rec_pkt")
    if SA.passport_app is None:
        LOGGER.error("passport app not detected")
        return {}
    SA.put_msg({"msg": request.json, "msg_type": "passport_recv_pkt",
                "source_app": "passport_app", "source_link": "", "pkt_rec_dt": time.time()})
    return "received"


@api_blueprint.route('/perf_test/', methods=["POST", "GET"])
def perf_test():
    LOGGER.debug("enter perf_test")
    try:
        f = open(r"./perf_test.json", "r")
        lines = f.readlines()
        f.close()
        SA.put_msg({"msg": lines, "msg_type": "perf_test",
                   "source_app": "", "source_link": "", "pkt_rec_dt": time.time()})
        return {"code": "0000", "message": "msg received"}

    except Exception as err:
        LOGGER.error(err)
    return {"code": "0000", "message": "msg received"}


@api_blueprint.route('/refresh_proto/<string:active_app>/', methods=["POST", "GET"])
def refresh_proto(active_app):
    tool = request.args.get('tool', "iptables")
    if tool in ["iptables", "acl"]:
        interceptor.enable(active_app=active_app, tool=tool)
    else:
        return {
            "code": "-1",
            "message": "the tool parameter don't exits! Please check your parameter"}
    return {"code": "0000", "message": f"{None}"}


@api_blueprint.route(f'/{RPDP_OVER_HTTP}/', methods=["POST", "GET"])
def recv_rpdp_msg():
    try:

        # LOGGER.debug(dir(request))
        # LOGGER.debug(request.remote_addr)
        msg = pickle.loads(request.data)
        src_link = msg["link_name"].split("_")
        src_link.insert(1, src_link.pop(-1))
        SA.put_msg({"msg": msg,
                    "source_link": "_".join(src_link),
                    "msg_type": f"{RPDP_OVER_HTTP}_recv_pkt",
                    "dst_sav_app": RPDP_ID,
                    "source_app": "",
                    "pkt_rec_dt": time.time()})
        return {"code": "0000", "message": "msg received"}
    except Exception as e:
        LOGGER.exception(e)
        return {"code": "5000", "message": f"{e}"}

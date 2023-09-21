#!/usr/bin/python3
# -*- encoding: utf-8 -*-
"""
@Time    :   2023/01/12 14:19:52
"""
import json
import time
from flask import Flask
from flask import request
from model import db
from model import SavInformationBase
from sav_agent import get_logger
from sav_agent import SavAgent
from sav_common import TIMEIT_THRESHOLD
from concurrent import futures
import grpc
import agent_msg_pb2
import agent_msg_pb2_grpc
from managers import iptables_refresh, router_acl_refresh


class GrpcServer(agent_msg_pb2_grpc.AgentLinkServicer):
    def __init__(self, agent, logger):
        super(GrpcServer, self).__init__()
        self.agent = agent
        self.logger = logger

    def Simple(self, req, context):
        t0 = time.time()
        msg_str = req.json_str
        req_src_ip = context.peer().split(":")[1]
        my_id = self.agent.config["rpdp_id"]
        reply = f"got {msg_str}"
        response = agent_msg_pb2.AgentMsg(sender_id=my_id, json_str=reply)
        try:
            msg_dict = {"msg": json.loads(msg_str)}
            # self.logger.debug(json.dumps(msg_dict, indent=2))
            req_dst_ip = msg_dict['msg']['dst_ip']
            msg_dict["source_app"] = sa.rpdp_app.name
            # TODO better ways to add source_link
            temp = msg_dict['msg']["protocol_name"].split("_")
            source_link = "_".join([temp[0], temp[2], temp[1]])
            msg_dict["source_link"] = source_link
            if not (source_link in self.agent.config["link_map"] and
                    self.agent.config["link_map"][source_link]["link_type"] == "grpc"):
                self.logger.warning(f"unexpected msg received: {msg_dict}")
                raise Exception("unexpected msg received")
            if not self.agent.config["grpc_config"]["server_enabled"]:
                self.logger.warning(
                    f"server disabled msg received: {msg_dict}")
                raise Exception("got msg on disabled server")
            msg_dict["msg_type"] = "grpc_msg"
            msg_dict["pkt_rec_dt"] = t0
            self.agent.put_msg(msg_dict)
            # self.agent.grpc_recv(msg_dict, req.sender_id)
        except Exception as err:
            self.logger.exception(err)
            self.logger.debug(msg_str)
            self.logger.error(f"grpc msg adding error: {err}")

        return response


LOGGER = get_logger("server")

# create and configure the app
app = Flask(__name__, instance_relative_config=True)
app.config.from_mapping(SECRET_KEY="dev",)
app_config = {
    "DEBUG": True,
    "SQLALCHEMY_TRACK_MODIFICATIONS": True,
    "SQLALCHEMY_POOL_SIZE": 20
}
app.config.from_object(app_config)
# ensure the instance folder exists
sa = SavAgent(
    logger=LOGGER, path_to_config=r"/root/savop/SavAgent_config.json")
# flask is used as a tunnel between reference_router and agent
grpc_server = None
quic_server = None
grpc_addr = None
quic_addr = None


def start_grpc(grpc_addr, logger):
    grpc_server = grpc.server(futures.ThreadPoolExecutor())
    agent_msg_pb2_grpc.add_AgentLinkServicer_to_server(
        GrpcServer(sa, logger), grpc_server)
    grpc_server.add_insecure_port(grpc_addr)
    grpc_server.start()
    return grpc_server


def _update_gprc_server(sa, logger, grpc_server, grpc_addr):
    if sa.config["grpc_config"]["server_enabled"]:
        new_addr = sa.config["grpc_config"]["server_addr"]
        if not grpc_server is None:
            if new_addr == grpc_addr:
                return grpc_server, grpc_addr
            logger.debug(grpc_server)
            grpc_server.stop(0)
        grpc_server = start_grpc(new_addr, logger)
        logger.debug(f"GRPC server updated at {new_addr}")
    else:
        if grpc_server is None:
            return grpc_server, grpc_addr
        logger.debug(grpc_server)
        grpc_server.stop(0)
        grpc_server = None
        logger.debug("GRPC server stopped")
        grpc_addr = None
    return grpc_server, grpc_addr


def _update_config(sa, logger, grpc_server, quic_server, grpc_addr, quic_addr, data=None):
    logger.debug("updating config")
    msg = None
    try:
        if data:
            data = json.loads(data)
            sa.update_config(data)
        grpc_server, grpc_addr = _update_gprc_server(
            sa, logger, grpc_server, grpc_addr)
        # quic_server,quic_addr = _update_quic_server(sa,logger,quic_server,quic_addr)
    except Exception as err:
        logger.error(err)
        msg = err
    return (msg, grpc_server, quic_server, grpc_addr, quic_addr)


@app.route("/bird_bgp_upload/", methods=["POST", "GET"])
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
                cmd = sa.rpdp_app.get_prepared_cmd()
                return {"code": "2000", "data": cmd, "message": "success"}
            except IndexError as err:
                pass
            t = time.time()-t0
            if t > TIMEIT_THRESHOLD:
                LOGGER.warning(f"TIMEIT {time.time()-t0:.4f} seconds")
            return rep
        msg["source_app"] = "rpdp_app"
        if m_t == "link_state_change":
            msg["source_link"] = msg["protocol_name"]
        else:
            msg["source_link"] = msg["msg"]["protocol_name"]
            if not m_t == "link_state_change":
                msg['link_type'] = "native_bgp"
                if "rpdp" in msg["msg"]["channels"]:
                    msg['link_type'] = "modified_bgp"
        msg["pkt_rec_dt"] = t0
        sa.put_msg(msg)
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


@app.route("/sib_table/", methods=["POST", "GET"])
def search_sib():
    """
    return the SIB table
    """
    sib_tables = db.session.query(SavInformationBase).all()
    data = {}
    for row in sib_tables:
        data[row.key] = json.loads(row.value)
    return json.dumps(data, indent=2)


@app.route('/refresh_proto/<string:active_app>/', methods=["POST", "GET"])
def refresh_proto(active_app):
    tool = request.args.get('tool')
    if (tool is None) or (tool == "iptables"):
        info = iptables_refresh(active_app, LOGGER)
    elif tool == "acl":
        info = router_acl_refresh(active_app, LOGGER)
    else:
        return {"code": "-1", "message": "the tool parameter don't exits! Please check your parameter"}
    return {"code": "0000", "message": f"{info}"}


@app.route('/update_config/', methods=["POST"])
def update_config():
    msg = "updated"
    temp, grpc_server, quic_server, grpc_addr, quic_addr = _update_config(
        sa, LOGGER, grpc_server, quic_server, grpc_addr, quic_addr, request.data)
    if temp:
        msg = temp
    return {"code": "0000", "message": msg}


@app.route('/metric/', methods=["POST", "GET"])
def metric():
    rep = {"agent": sa.data["metric"]}
    if sa.rpdp_app:
        rep[sa.rpdp_app.name] = sa.rpdp_app.metric
    if sa.passport_app:
        rep[sa.passport_app.name] = sa.passport_app.metric
    return json.dumps(rep, indent=2)


@app.route('/savop_quic/', methods=["POST"])
def savop_quic():
    t0 = time.time()
    if sa.config["quic_config"]["server_enabled"]:
        msg = json.loads(request.data.decode())
        msg = {
            "msg": msg,
            "source_app": sa.rpdp_app.name,
            "link_type": "quic",
            "msg_type": "quic_msg",
            "source_link": msg["dummy_link"],
            "pkt_rec_dt": t0
        }
        try:
            sa.put_msg(msg)
        except Exception as err:
            LOGGER.error(err)
        return {"code": "0000", "message": "msg received"}
    else:
        LOGGER.warning(f"quic got unexpected msg:{request.data.decode()}")
        return {"code": "5004", "message": "quic server disabled"}


@app.route('/reset_metric/', methods=["POST", "GET"])
def reset_metric():
    sa.data["msg_count"] = 0
    sa.rpdp_app.reset_metric()
    LOGGER.debug(F"PERF-TEST: TEST BEGIN at {time.time()}")
    return {"code": "0000", "message": "reset received"}

    # the returned value is not used by client
_, grpc_server, quic_server, grpc_addr, quic_addr = _update_config(
    sa, LOGGER, grpc_server, quic_server, grpc_addr, quic_addr)


@app.route('/long_nlri_test/', methods=["POST", "GET"])
def long_nlri_test():
    LOGGER.debug(F"got long_nlri_test at {time.time()}")
    try:
        bgp_sample = {"as_path": "2,1,0,0,255,222",
                      "as_path_len": 6,
                      "is_interior": 1,
                      "next_hop": "4,10,0,1,1",
                      "nlri_len": 4, "protocol_name": "savbgp_65502_65501",
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


@app.route('/passport_key_exchange/', methods=['GET', 'POST'])
def passport_key_exchange():
    # LOGGER.debug(request.json)
    if sa.passport_app is None:
        LOGGER.error("passport app not detected")
        return None

    msg = {
        "msg_type": "passport_key_exchange",
        "msg": request.json,
        "source_app": "passport_app",
        "source_link": "",
        "pkt_rec_dt": time.time()
    }
    sa.put_msg(msg)
    return sa.passport_app.get_public_key_dict()


@app.route('/passport_send_pkt/', methods=['GET', 'POST'])
def passport_send_pkt():
    if sa.passport_app is None:
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
    sa.put_msg(msg)
    # LOGGER.debug("good")
    return "received"


@app.route('/passport_rec_pkt/', methods=['GET', 'POST'])
def passport_rec_pkt():
    if sa.passport_app is None:
        LOGGER.error("passport app not detected")
        return {}
    sa.put_msg({"msg": request.json, "msg_type": "passport_recv_pkt",
                "source_app": "passport_app", "source_link": "", "pkt_rec_dt": time.time()})
    return "received"


@app.route('/perf_test/', methods=["POST", "GET"])
def perf_test():
    LOGGER.debug("got perf test")
    try:
        f = open(r"./perf_test.json", "r")
        lines = f.readlines()
        f.close()
        sa.put_msg({"msg": lines, "msg_type": "perf_test",
                   "source_app": "", "source_link": "", "pkt_rec_dt": time.time()})
        return {"code": "0000", "message": "msg received"}

    except Exception as err:
        LOGGER.error(err)
    return {"code": "0000", "message": "msg received"}


if __name__ == '__main__':
    app.run("0.0.0.0:8888", debug=True)

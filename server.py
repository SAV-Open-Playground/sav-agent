#!/usr/bin/python3
# -*- encoding: utf-8 -*-
"""
@Time    :   2023/01/12 14:19:52
"""
import json
from flask import Flask
from flask import request
from model import db
from model import SavInformationBase
from sav_agent import get_logger
from sav_agent import SavAgent
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
        msg_str = req.json_str
        req_src_ip = context.peer().split(":")[1]
        # self.logger.debug(f"grpc got msg from {req.sender_id}")
        # self.logger.debug(msg)
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
            self.agent.put_msg(msg_dict)
            # self.agent.grpc_recv(msg_dict, req.sender_id)
        except Exception as err:
            self.logger.debug(msg_str)
            self.logger.error(f"grpc msg adding error: {err}")
        
        return response


LOGGER = get_logger("server")

# create and configure the app
app = Flask(__name__, instance_relative_config=True)
app.config.from_mapping(SECRET_KEY="dev",)
app_config = {
    "DEBUG": True,
    "SQLALCHEMY_TRACK_MODIFICATIONS": True
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
    try:
        msg = json.loads(request.data)
    except Exception as err:
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
            cmd = sa.rpdp_app.get_prepared_cmd()
            return {"code": "2000", "data": cmd, "message": "success"}
        msg["source_app"] = sa.rpdp_app.name
        if m_t == "link_state_change":
            msg["source_link"] = msg["protocol_name"]
        else:
            msg["source_link"] = msg["msg"]["protocol_name"]
            if not m_t == "link_state_change":
                msg['link_type'] = "native_bgp"
                if "rpdp" in msg["msg"]["channels"]:
                    msg['link_type'] = "modified_bgp"
        sa.put_msg(msg)
        return {"code": "0000", "message": "success"}
    except Exception as err:
        LOGGER.error(msg)
        LOGGER.error(err)
        return {"code": "5004", "message": str(err), "data": str(request.data)}


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
        return {"code": "-1", "message": "the tool parameter don't exits! Please checkout your parameter"}
    return {"code": "0000", "message": f"{info}"}


@app.route('/update_config/', methods=["POST"])
def update_config():
    msg = "updated"
    temp, grpc_server, quic_server, grpc_addr, quic_addr = _update_config(
        sa, LOGGER, grpc_server, quic_server, grpc_addr, quic_addr, request.data)
    if temp:
        msg = temp
    return {"code": "0000", "message": msg}


@app.route('/savop_quic/', methods=["POST"])
def savop_quic():
    if sa.config["quic_config"]["server_enabled"]:
        msg = json.loads(request.data.decode())
        msg = {
            "msg": msg,
            "source_app": sa.rpdp_app.name,
            "link_type": "quic",
            "msg_type": "quic_msg",
            "source_link": msg["dummy_link"]
        }
        try:
            sa.put_msg(msg)
        except Exception as err:
            LOGGER.error(err)
        return {"code": "0000", "message": "msg received"}
    else:
        LOGGER.warning(f"quic got unexpected msg:{request.data.decode()}")
        return {"code": "5004", "message": "quic server disabled"}

    # the returned value is not used by client
_, grpc_server, quic_server, grpc_addr, quic_addr = _update_config(
    sa, LOGGER, grpc_server, quic_server, grpc_addr, quic_addr)

if __name__ == '__main__':
    app.run("0.0.0.0:8888")

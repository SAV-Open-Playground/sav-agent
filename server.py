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
from iptable_manager import iptables_refresh

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
sa = SavAgent(logger=LOGGER, path_to_config=r"/root/savop/SavAgent_config.json")
# flask is used as a tunnel between reference_router and agent


class GrpcServer(agent_msg_pb2_grpc.AgentLinkServicer):
    def __init__(self, agent, logger):
        super(GrpcServer, self).__init__()
        self.agent = agent
        self.logger = logger

    def Simple(self, req, context):
        
        msg_str = req.json_str
        self.logger.debug(f"grpc server got msg {msg_str} from {req.sender_id}")
        my_id = self.agent.config.get("grpc_id")
        reply = f"got {msg_str}"
        try:
            msg_dict = json.loads(msg_str)
            self.agent.grpc_app.recv_msg(msg_dict, req.sender_id)
        except Exception as err:
            self.logger.debug(msg_str)
            self.logger.error(f"grpc msg adding error: {err}")

        response = agent_msg_pb2.AgentMsg(sender_id=my_id,
                                          json_str=reply)
        return response


if sa.config.get("grpc_enabled"):
    grpc_server = grpc.server(futures.ThreadPoolExecutor())
    agent_msg_pb2_grpc.add_AgentLinkServicer_to_server(
        GrpcServer(sa, LOGGER), grpc_server)
    addr = sa.config.get("grpc_server_addr")
    grpc_server.add_insecure_port(addr)
    grpc_server.start()
    LOGGER.debug(f"GRPC server running at {addr}")


@app.route("/bird_bgp_upload/", methods=["POST", "GET"])
def index():
    """
    the entrypoint for reference_router
    """
    try:
        data = json.loads(request.data)
    except Exception as err:
        LOGGER.error(err)
        return {"code": "5001", "message": "Invalid Json String", "data": str(request.data)}
    try:
        rpdp_app = sa.rpdp_app
        required_keys = ["msg_type", "msg"]
        for key in required_keys:
            if key not in data:
                LOGGER.warning(f"{key} not found in {data.keys()}")
                return {"code": "5002", "message": f"{key} not found!"}
        if data["msg_type"] == "request_cmd":
            cmd = rpdp_app.get_prepared_cmd()
            return {"code": "2000", "data": cmd, "message": "success"}
        # LOGGER.debug(data)
        rpdp_app.recv_msg(data)
        return {"code": "0000", "message": "success"}
    except Exception as err:
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
        data[row.key]=json.loads(row.value)
    return json.dumps(data, indent=2)


@app.route('/refresh_proto/<string:active_app>/', methods=["POST", "GET"])
def refresh_proto(active_app):
    info = iptables_refresh(active_app,LOGGER)
    return {"code": "0000", "message": f"{info}"}


if __name__ == '__main__':
    app.run(host="0.0.0.0", port=8888)

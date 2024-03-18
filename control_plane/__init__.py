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
import time
import json
from common.main_logger import LOGGER
from control_plane.sav_agent import *
from concurrent import futures
import grpc
from control_plane import agent_msg_pb2, agent_msg_pb2_grpc

GRPC_SERVER = None
GRPC_SERVER = None
QUIC_SERVER = None
GRPC_ADDR = None
QUIC_ADDR = None
SA_CFG_PATH = r"/root/savop/SavAgent_config.json"

SA = SavAgent(logger=LOGGER, path_to_config=SA_CFG_PATH)

class GrpcServer(agent_msg_pb2_grpc.AgentLinkServicer):
    def __init__(self, agent, logger):
        super(GrpcServer, self).__init__()
        self.agent = agent
        self.logger = logger

    def Simple(self, req, context):
        t0 = time.time()
        msg_str = req.json_str
        req_src_ip = context.peer().split(":")[1]
        my_id = self.agent.config["router_id"]
        reply = f"got {msg_str}"
        response = agent_msg_pb2.AgentMsg(sender_id=my_id, json_str=reply)
        try:
            msg_dict = {"msg": json.loads(msg_str)}
            # self.logger.debug(json.dumps(msg_dict, indent=2))
            req_dst_ip = msg_dict['msg']['dst_ip']
            msg_dict["source_app"] = SA.rpdp_app.app_id
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
        except Exception as err:
            self.logger.exception(err)
            self.logger.debug(msg_str)
            self.logger.error(f"grpc msg adding error: {err}")

        return response

def start_grpc(grpc_addr, logger):
    LOGGER.debug("starting grpc server")
    grpc_server = grpc.server(futures.ThreadPoolExecutor())
    agent_msg_pb2_grpc.add_AgentLinkServicer_to_server(
        GrpcServer(SA, logger), grpc_server)
    grpc_server.add_insecure_port(grpc_addr)
    grpc_server.start()
    return grpc_server


def _update_gprc_server(logger):
    LOGGER.debug("updating grpc server")
    if SA.config["grpc_config"]["server_enabled"]:
        new_addr = SA.config["grpc_config"]["server_addr"]
        if GRPC_SERVER:
            if new_addr == GRPC_ADDR:
                return
            logger.debug(GRPC_SERVER)
            GRPC_SERVER.stop(0)
        GRPC_SERVER = start_grpc(new_addr, logger)
        GRPC_ADDR = new_addr
        logger.debug(f"GRPC server running at {new_addr}")
    else:
        if GRPC_SERVER is None:
            return
        logger.debug(GRPC_SERVER)
        GRPC_SERVER.stop(0)
        GRPC_SERVER = None
        logger.debug("GRPC server stopped")
        GRPC_ADDR = None
    return


def _update_config():
    """
    reserved for future use
    """
    LOGGER.debug("updating config")
    SA.update_config()
    LOGGER.debug("SA config updated")
    return ""

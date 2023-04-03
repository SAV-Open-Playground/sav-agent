#!/usr/bin/python3
# -*- encoding: utf-8 -*-
"""
@Time    :   2023/01/12 14:19:52
"""

import os
import json

from flask import Flask
from flask import request

from model import db
from model import SavInformationBase
from sav_agent import get_logger
from sav_agent import SavAgent
import config
CUR_DIR = os.path.dirname(os.path.abspath(__file__))

LOGGER = get_logger("server")

# create and configure the app
app = Flask(__name__, instance_relative_config=True)
app.config.from_mapping(
    SECRET_KEY="dev",
)

app.config.from_object(config)

# ensure the instance folder exists
if not os.path.exists(path=CUR_DIR + "/data/"):
    os.makedirs(CUR_DIR + "/data/")


sa = SavAgent(app,
              logger=LOGGER,
              path_to_config=r"/root/savop/SavAgent_config.json")
# flask is used as a tunnel between bird and agent


@app.route("/bird_bgp_upload/", methods=["POST", "GET"])
def index():
    """
    the entrypoint for modified bird instance
    """
    try:
        data = json.loads(request.data)
    except Exception as err:
        LOGGER.error(err)
        return {"code": "5001", "message": "Invalid Json String", "data": str(request.data)}
    try:
        bird_app = sa.bird_app
        required_keys = ["msg_type", "msg"]
        for key in required_keys:
            if key not in data:
                return {"code": "5002", "message": f"{key} not found!"}
        if data["msg_type"] == "request_cmd":
            cmd = bird_app.get_prepared_cmd()
            return {"code": "2000", "data": cmd, "message": "success"}

        bird_app.recv_msg(data)
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
    data = []
    for row in sib_tables:
        data.append({"id": row.id,
                     "prefix": row.prefix,
                     "neighbor_as": row.neighbor_as,
                     "interface": row.interface,
                     "source": row.source,
                     "direction": row.direction,
                     "createtime": row.createtime})
    return data

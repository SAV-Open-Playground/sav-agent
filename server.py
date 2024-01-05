#!/usr/bin/python3
# -*- encoding: utf-8 -*-
"""
@Time    :   2023/01/12 14:19:52
"""
from flask import Flask
from restful_api.api import api_blueprint

# create and configure the app
app = Flask(__name__, instance_relative_config=True)
app.config.from_mapping(SECRET_KEY="dev", )
app_config = {
    "DEBUG": True
}
app.config.from_object(app_config)
app.register_blueprint(api_blueprint)


if __name__ == '__main__':
    app.run(host="0.0.0.0", port="8888", debug=True)

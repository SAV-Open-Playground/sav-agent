#!/usr/bin/python3
# -*- encoding: utf-8 -*-
"""
@Time    :   2023/01/12 14:20:15
"""


import os
DEBUG = True
SQLALCHEMY_DATABASE_URI = 'sqlite:///' + \
    os.path.dirname(os.path.abspath(__file__)) + "/data/sib.sqlite"
SQLALCHEMY_TRACK_MODIFICATIONS = True

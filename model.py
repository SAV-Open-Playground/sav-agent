#!/usr/bin/python3
# -*- encoding: utf-8 -*-
"""
@Time    :   2023/01/17 16:04:22
"""
# from flask_sqlalchemy import SQLAlchemy
import os
from sqlalchemy import create_engine
from sqlalchemy import Column, Integer, String, DateTime, func
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker

Base = declarative_base()


class SavInformationBase(Base):
    """
    define sav information base data model
    this table holds everything we need for SAV
    """
    __tablename__ = 'SIB'
    id = Column(Integer, primary_key=True, autoincrement=True)  # key name
    value = Column(String(1024*1024*8), nullable=False)
    key = Column(String(64), nullable=False)
    createtime = Column(DateTime, server_default=func.now())
    updatetime = Column(DateTime, server_default=func.now(),
                        onupdate=func.now())

    def __init__(self, key, value):
        self.key = key
        self.value = value

    def __repr__(self):
        return '<id %r>' % self.id


class SavTable(Base):
    """
    define sav table base data model
    """
    __tablename__ = 'STB'
    id = Column(Integer, primary_key=True, autoincrement=True)
    prefix = Column(String(256), nullable=False)
    neighbor_as = Column(Integer, nullable=True)
    # interface = Column(Integer, nullable=False)
    # interface should be an Integer that stand for the physical network interface.
    # Use string here temporarily.
    interface = Column(String(120), nullable=False)
    source = Column(String(120), nullable=True)
    direction = Column(String(120), nullable=True)
    createtime = Column(DateTime, server_default=func.now())
    updatetime = Column(DateTime, server_default=func.now(),
                        onupdate=func.now())
    source = Column(String(20), nullable=True)
    local_role = Column(String(10), nullable=False)

    def __init__(self, prefix, neighbor_as, interface, local_role,source=None, direction=None):
        self.prefix = prefix
        self.neighbor_as = neighbor_as
        self.interface = interface
        self.source = source
        self.direction = direction
        self.local_role = local_role

    def __repr__(self):
        return '<id %r>' % self.id


class DataBase():
    def __init__(self):
        cur_dir = os.path.dirname(os.path.abspath(__file__))
        if not os.path.exists(path=cur_dir + "/data/"):
            os.makedirs(cur_dir + "/data/")
        DB_URI = f"sqlite:///{cur_dir}/data/sib.sqlite"
        self.engine = create_engine(DB_URI, pool_size=8,  pool_recycle=60*30)
        self.DBsession = sessionmaker(bind=self.engine)
        Base.metadata.drop_all(self.engine)
        Base.metadata.create_all(self.engine)

    @property
    def session(self):
        return self.DBsession()


# ensure the instance folder exists
db = DataBase()
session = db.session

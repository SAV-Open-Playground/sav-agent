#!/usr/bin/python3
# -*- encoding: utf-8 -*-
"""
@Time    :   2023/01/17 16:04:22
"""
# from flask_sqlalchemy import SQLAlchemy
import os
from sqlalchemy import create_engine
from sqlalchemy import Column, Integer, String, DateTime, Boolean, func
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker

Base = declarative_base()


class SavInformationBase(Base):
    """
    define sav information base data model
    """
    __tablename__ = 'SIB'
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

    def __init__(self, prefix, neighbor_as, interface, source=None, direction=None):
        self.prefix = prefix
        self.neighbor_as = neighbor_as
        self.interface = interface
        self.source = source
        self.direction = direction

    def __repr__(self):
        return '<id %r>' % self.id


class DataBase():
    DB_URI = 'sqlite:///' + \
        os.path.dirname(os.path.abspath(__file__)) + "/data/sib.sqlite"
    engine = create_engine(DB_URI, pool_size=8,  pool_recycle=60*30)
    DBsession = sessionmaker(bind=engine)

    def create_all(self):
        Base.metadata.create_all(self.engine)

    def drop_all(self):
        Base.metadata.drop_all(self.engine)

    @property
    def session(self):
        return self.DBsession()


db = DataBase()

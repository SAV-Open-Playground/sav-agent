# -*- coding: utf-8 -*-
"""
-------------------------------------------------
   File Name:     logger
   Description :
   Author :       MichaelYoung
   date:          2024/1/3
-------------------------------------------------
   Change Activity:
                   2024/1/3:
-------------------------------------------------
"""
import os
import time
import logging
import logging.handlers


def get_logger(file_name):
    """
    get logger function for all modules
    """
    maxsize = 1024 * 1024 * 50
    backup_num = 1
    level = logging.WARN
    level = logging.DEBUG
    logger = logging.getLogger(__name__)
    logger.setLevel(level)
    log_file = os.path.dirname(os.path.abspath(__file__))
    log_file = os.path.dirname(os.path.dirname(log_file))
    log_file = os.path.join(log_file, "logs", f"{file_name}.log")
    with open(log_file, "w") as f:
        pass
    handler = logging.handlers.RotatingFileHandler(
        log_file,
        maxBytes=maxsize,
        backupCount=backup_num)
    handler.setLevel(level)

    formatter = logging.Formatter(
        "[%(asctime)s]  [%(filename)s:%(lineno)s-%(funcName)s] [%(levelname)s] %(message)s")
    formatter.converter = time.gmtime
    handler.setFormatter(formatter)

    logger.addHandler(handler)
    return logger


LOGGER = get_logger("server")

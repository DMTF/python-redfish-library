# Copyright Notice:
# Copyright 2016-2021 DMTF. All rights reserved.
# License: BSD 3-Clause License. For full text see link:
# https://github.com/DMTF/python-redfish-library/blob/master/LICENSE.md

""" Redfish restful library """

__all__ = ['rest', 'ris', 'discovery']
__version__ = "3.0.3"

from redfish.rest.v1 import redfish_client
from redfish.rest.v1 import AuthMethod
from redfish.discovery.discovery import discover_ssdp
import logging

def redfish_logger(file_name, log_format, log_level=logging.ERROR):
    formatter = logging.Formatter(log_format)
    fh = logging.FileHandler(file_name)
    fh.setFormatter(formatter)
    logger = logging.getLogger(__name__)
    logger.addHandler(fh)
    logger.setLevel(log_level)
    return logger

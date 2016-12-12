""" Redfish restful library """

__all__ = ['rest', 'ris']
__version__ = "1.0.0"

from redfish.rest.v1 import redfish_client
from redfish.rest.v1 import AuthMethod
import logging

def redfish_logger(file_name, log_format, log_level=logging.ERROR):
    formatter = logging.Formatter(log_format)
    fh = logging.FileHandler(file_name)
    fh.setFormatter(formatter)
    logger = logging.getLogger(__name__)
    logger.addHandler(fh)
    logger.setLevel(log_level)
    return logger

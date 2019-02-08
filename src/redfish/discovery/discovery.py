# Copyright Notice:
# Copyright 2016-2019 DMTF. All rights reserved.
# License: BSD 3-Clause License. For full text see link: https://github.com/DMTF/python-redfish-library/blob/master/LICENSE.md

# -*- coding: utf-8 -*-
"""Discovers Redfish services"""

import re
import socket

from six.moves import http_client
from six import BytesIO

class FakeSocket():
    """Helper class to force raw data into an HTTP Response structure"""
    def __init__(self, response_str):
        self._file = BytesIO(response_str)
    def makefile(self, *args, **kwargs):
        return self._file

def discover_ssdp(port=1900, ttl=2, response_time=3):
    """Discovers Redfish services via SSDP

    :param port: the port to use for the SSDP request
    :type port: int
    :param ttl: the time-to-live value for the request
    :type ttl: int
    :param response_time: the number of seconds in which a service can respond
    :type response_time: int

    :returns: a set of discovery data
    """
    # Sanity check the inputs
    if response_time < 1:
        response_time = 1
    if ttl < 1:
        ttl = 1
    if ttl > 255:
        ttl = 255

    # Initialize the multicast data
    mcast_ip = '239.255.255.250'
    msearch_str = ( 'M-SEARCH * HTTP/1.1\r\n'
                    'Host: {}:{}\r\n'
                    'Man: "ssdp:discover"\r\n'
                    'ST: urn:dmtf-org:service:redfish-rest:1\r\n'
                    'MX: {}\r\n'
                  ).format(mcast_ip, port, response_time)
    socket.setdefaulttimeout(response_time + 2)

    # Set up the socket and send the request
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_TTL, ttl)
    sock.sendto(bytearray(msearch_str, 'utf-8'), (mcast_ip, port))

    # On the same socket, wait for responses
    discovered_services = {}
    while True:
        try:
            response = http_client.HTTPResponse(FakeSocket(sock.recv(1024)))
            response.begin()
            uuid_search = re.search('^uuid:([a-f0-9\-]*)::urn:dmtf-org:service:redfish-rest:1(:\d)?$', response.getheader('USN').lower())
            if uuid_search:
                discovered_services[uuid_search.group(1)] = response.getheader('AL')
        except socket.timeout:
            # We hit the timeout; done waiting for responses
            break

    sock.close()
    return discovered_services

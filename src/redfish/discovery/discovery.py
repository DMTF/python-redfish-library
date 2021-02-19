# Copyright Notice:
# Copyright 2016-2021 DMTF. All rights reserved.
# License: BSD 3-Clause License. For full text see link:
# https://github.com/DMTF/python-redfish-library/blob/master/LICENSE.md

# -*- coding: utf-8 -*-
"""Discovers Redfish services"""

import http.client
import re
import socket

from io import BytesIO


class FakeSocket:
    """Helper class to force raw data into an HTTP Response structure"""

    def __init__(self, response_str):
        self._file = BytesIO(response_str)

    def makefile(self, *args, **kwargs):
        return self._file


def sanitize(number, minimum, maximum=None):
    """ Sanity check a given number.

    :param number: the number to check
    :param minimum: the minimum acceptable number
    :param maximum: the maximum acceptable number (optional)

    if maximum is not given sanitize return the given value superior
    at minimum

    :returns: an integer who respect the given allowed minimum and maximum
    """
    if number < minimum:
        number = minimum
    elif maximum is not None and number > maximum:
        number = maximum
    return number


def discover_ssdp(port=1900, ttl=2, response_time=3, iface=None, protocol="ipv4", address=None):
    """Discovers Redfish services via SSDP

    :param port: the port to use for the SSDP request
    :type port: int
    :param ttl: the time-to-live value for the request
    :type ttl: int
    :param response_time: the number of seconds in which a service can respond
    :type response_time: int
    :param iface: the interface to use for the request; None for all
    :type iface: string
    :param protocol: the type of protocol to use for the request; either 'ipv4' or 'ipv6'
    :type protocol: string
    :param address: the address to use for the request; None for all 
    :type address: string

    :returns: a set of discovery data
    """
    # Sanity check the inputs
    valid_protocols = ("ipv4", "ipv6")
    if protocol not in valid_protocols:
        raise ValueError("Invalid protocol type. Expected one of: {}".format(valid_protocols))
    ttl = sanitize(ttl, minimum=1, maximum=255)
    response_time = sanitize(response_time, minimum=1)

    if protocol == "ipv6":
        mcast_ip = "ff02::c"
        mcast_connection = (mcast_ip, port, 0, 0)
        af_type = socket.AF_INET6
    elif protocol == "ipv4":
        mcast_ip = "239.255.255.250"
        mcast_connection = (mcast_ip, port)
        af_type = socket.AF_INET

    # Initialize the multicast data
    msearch_str = (
        "M-SEARCH * HTTP/1.1\r\n"
        "Host: {}:{}\r\n"
        'Man: "ssdp:discover"\r\n'
        "ST: urn:dmtf-org:service:redfish-rest:1\r\n"
        "MX: {}\r\n"
    ).format(mcast_ip, port, response_time)
    socket.setdefaulttimeout(response_time + 2)

    # Set up the socket and send the request
    sock = socket.socket(af_type, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_TTL, ttl)
    if address:
        sock.bind((address, 0))
    if iface:
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_BINDTODEVICE, str(iface+"\0").encode("utf-8"))
    sock.sendto(bytearray(msearch_str, "utf-8"), mcast_connection)

    # On the same socket, wait for responses
    discovered_services = {}
    pattern = re.compile(
        "^uuid:([a-f0-9\-]*)::urn:dmtf-org:service:redfish-rest:1(:\d)?$") # noqa
    while True:
        try:
            response = http.client.HTTPResponse(FakeSocket(sock.recv(1024)))
            response.begin()
            uuid_search = pattern.search(response.getheader("USN").lower())
            if uuid_search:
                discovered_services[uuid_search.group(1)] = response.getheader(
                    "AL"
                )
        except socket.timeout:
            # We hit the timeout; done waiting for responses
            break

    sock.close()
    return discovered_services

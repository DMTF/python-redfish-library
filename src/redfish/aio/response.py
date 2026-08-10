# Copyright Notice:
# Copyright 2016-2026 DMTF. All rights reserved.
# License: BSD 3-Clause License. For full text see link:
# https://github.com/DMTF/python-redfish-library/blob/main/LICENSE.md

"""Cached request and response objects for asynchronous Redfish operations."""

from dataclasses import dataclass
import json

from multidict import CIMultiDict

from .exceptions import RedfishProtocolError


@dataclass(frozen=True)
class AsyncRestRequest:
    """Description of an asynchronous Redfish request."""

    path: str
    method: str = "GET"
    body: object = None


class AsyncRestResponse:
    """Cached response returned by an asynchronous Redfish request."""

    def __init__(self, request, status, headers, read, encoding="utf-8"):
        self._request = request
        self._status = status
        self._headers = CIMultiDict(headers)
        self._read = read
        self._encoding = encoding

    @property
    def read(self):
        """Return the raw response body."""
        return self._read

    @property
    def status(self):
        """Return the HTTP status code."""
        return self._status

    @property
    def text(self):
        """Return the decoded response body."""
        return self._read.decode(self._encoding, "replace")

    @property
    def dict(self):
        """Return the response body decoded as JSON."""
        if not self._read:
            return {}
        try:
            return json.loads(self.text)
        except (TypeError, ValueError) as exc:
            raise RedfishProtocolError(
                "Service responded with invalid JSON at URI {}".format(
                    self._request.path
                )
            ) from exc

    @property
    def request(self):
        """Return the request that produced this response."""
        return self._request

    def getheaders(self):
        """Return all response headers."""
        return list(self._headers.items())

    def getheader(self, name):
        """Return one response header case-insensitively."""
        return self._headers.get(name)

# Copyright Notice:
# Copyright 2016-2026 DMTF. All rights reserved.
# License: BSD 3-Clause License. For full text see link:
# https://github.com/DMTF/python-redfish-library/blob/main/LICENSE.md

"""Exceptions raised by the asynchronous Redfish client."""


class RedfishError(Exception):
    """Base exception for asynchronous Redfish operations."""


class RedfishConnectionError(RedfishError):
    """Raised when the Redfish service cannot be reached."""


class RedfishTimeoutError(RedfishConnectionError):
    """Raised when a Redfish operation times out."""


class RedfishInvalidTargetError(RedfishError):
    """Raised when a target is invalid or outside the configured origin."""


class RedfishAuthenticationError(RedfishError):
    """Raised when the Redfish service rejects authentication."""


class RedfishPasswordChangeRequiredError(RedfishAuthenticationError):
    """Raised when authentication requires a password change."""

    def __init__(self, password_change_uri=None):
        super().__init__("Redfish service requires a password change")
        self.password_change_uri = password_change_uri


class RedfishHTTPError(RedfishError):
    """Raised when a Redfish service returns an unsuccessful HTTP status."""

    def __init__(self, response):
        super().__init__(
            "Redfish request returned HTTP {}".format(response.status)
        )
        self.response = response


class RedfishProtocolError(RedfishError):
    """Raised when a Redfish resource is malformed."""

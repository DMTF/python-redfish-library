# Copyright Notice:
# Copyright 2016-2026 DMTF. All rights reserved.
# License: BSD 3-Clause License. For full text see link:
# https://github.com/DMTF/python-redfish-library/blob/main/LICENSE.md

"""Asynchronous Redfish client implemented with aiohttp."""

import asyncio
import base64
import warnings

import aiohttp
from multidict import CIMultiDict
from yarl import URL

from .exceptions import (
    RedfishAuthenticationError,
    RedfishConnectionError,
    RedfishHTTPError,
    RedfishInvalidTargetError,
    RedfishPasswordChangeRequiredError,
    RedfishProtocolError,
    RedfishTimeoutError,
)
from .response import AsyncRestRequest, AsyncRestResponse


SESSION_COLLECTION_PATH = "/redfish/v1/SessionService/Sessions"


class AsyncRedfishClient:
    """Perform asynchronous Redfish requests with an injected session."""

    def __init__(
        self,
        base_url,
        username=None,
        password=None,
        session=None,
        timeout=None,
        default_prefix="/redfish/v1/",
        session_key=None,
        session_location=None,
    ):
        if session is None:
            raise ValueError(
                "A caller-owned aiohttp.ClientSession is required"
            )
        if (username is None) != (password is None):
            raise ValueError("Username and password must be provided together")
        if session_location is not None and session_key is None:
            raise ValueError("Session location requires a session key")

        try:
            url = URL(base_url)
        except (TypeError, ValueError) as exc:
            raise ValueError("Invalid Redfish base URL") from exc
        if (
            url.scheme not in ("http", "https")
            or url.host is None
            or url.user is not None
            or url.password is not None
            or url.path not in ("", "/")
            or url.query_string
            or url.fragment
        ):
            raise ValueError("Invalid Redfish base URL")

        self._base_url = (
            url.with_path("/").with_query(None).with_fragment(None)
        )
        self._session = session
        self._timeout = self._make_timeout(timeout)
        self._default_prefix = default_prefix
        self._auth_lock = asyncio.Lock()
        self._username = username
        self._password = password
        if session_key is not None and (
            not isinstance(session_key, str) or not session_key.strip()
        ):
            raise ValueError("Session key must be a non-empty string")
        if session_key is not None and self._base_url.scheme != "https":
            raise ValueError("Redfish authentication requires HTTPS")
        if session_location is not None and (
            not isinstance(session_location, str)
            or not session_location.strip()
        ):
            raise ValueError("Session location must be a non-empty string")
        if session_location is not None:
            self._resolve_url(session_location)
        self._session_key = session_key
        self._session_location = session_location
        self._authorization = None

    async def __aenter__(self):
        try:
            await self.login()
        except RedfishPasswordChangeRequiredError:
            await self.logout()
            raise
        return self

    async def __aexit__(self, exc_type, exc_value, traceback):
        await self.logout()

    async def login(self, auth="session"):
        """Authenticate with the Redfish service."""
        if auth not in ("basic", "session"):
            raise ValueError("Unsupported Redfish authentication method")
        if self._username is None:
            raise ValueError("Username and password are required")
        if self._base_url.scheme != "https":
            raise ValueError("Redfish authentication requires HTTPS")
        if auth == "basic" and ":" in self._username:
            raise ValueError(
                "Basic authentication username cannot contain ':'"
            )

        async with self._auth_lock:
            if (
                self._session_key is not None
                or self._authorization is not None
            ):
                await self._logout_locked()
            if auth == "basic":
                encoded = base64.b64encode(
                    "{}:{}".format(
                        self._username, self._password
                    ).encode("utf-8")
                ).decode("ascii")
                self._authorization = "Basic {}".format(encoded)
                return
            await self._login_session()

    async def _login_session(self):
        root_response = await self._request(
            self._default_prefix, authenticated=False
        )
        if root_response.status == 401:
            warnings.warn(
                "Service incorrectly responded with HTTP 401 Unauthorized "
                "for the service root; contact the vendor",
                stacklevel=2,
            )
            target = SESSION_COLLECTION_PATH
        else:
            self._ensure_success(root_response)
            root = root_response.dict
            if not isinstance(root, dict):
                raise RedfishProtocolError(
                    "Redfish resource at {} is not a JSON object".format(
                        self._default_prefix
                    )
                )
            links = root.get("Links")
            sessions = (
                links.get("Sessions") if isinstance(links, dict) else None
            )
            target = (
                sessions.get("@odata.id")
                if isinstance(sessions, dict)
                else None
            )
            if not isinstance(target, str) or not target.strip():
                target = SESSION_COLLECTION_PATH
        response = await self._request(
            target,
            method="POST",
            body={"UserName": self._username, "Password": self._password},
            authenticated=False,
            sensitive_body=True,
        )
        password_change_uri = self._get_password_change_uri(response)
        if not 200 <= response.status < 300:
            self._ensure_success(response)
        session_key = response.getheader("X-Auth-Token")
        session_location = response.getheader("Location")
        if (
            not isinstance(session_location, str)
            or not session_location.strip()
        ):
            response_body = response.dict
            if isinstance(response_body, dict):
                session_location = response_body.get("@odata.id")
        if (
            not isinstance(session_key, str)
            or not session_key.strip()
            or not isinstance(session_location, str)
            or not session_location.strip()
        ):
            raise RedfishProtocolError(
                "Redfish session response is missing authentication data"
            )
        self._resolve_url(session_location)
        self._authorization = None
        self._session_key = session_key
        self._session_location = session_location
        if password_change_uri is not False:
            raise RedfishPasswordChangeRequiredError(password_change_uri)

    async def _refresh_session(self, expired_session_key):
        async with self._auth_lock:
            if self._session_key != expired_session_key:
                return self._session_key is not None
            self._session_key = None
            self._session_location = None
            await self._login_session()
            return True

    async def _logout_locked(self):
        response = None
        try:
            if (
                self._session_key is not None
                and self._session_location is not None
            ):
                response = await self.delete(self._session_location)
        finally:
            self._session_key = None
            self._session_location = None
            self._authorization = None
        if response is not None and response.status not in (401, 404):
            self._ensure_success(response)

    async def logout(self):
        """Terminate Redfish login without closing the transport."""
        async with self._auth_lock:
            await self._logout_locked()

    @staticmethod
    def _make_timeout(timeout):
        if timeout is None or isinstance(timeout, aiohttp.ClientTimeout):
            return timeout
        if not isinstance(timeout, (int, float)) or timeout < 0:
            raise ValueError("Timeout must be a non-negative number")
        return aiohttp.ClientTimeout(total=timeout)

    def _resolve_url(self, target):
        try:
            target_url = self._base_url.join(URL(target))
            if target_url.user is not None or target_url.password is not None:
                raise RedfishInvalidTargetError(
                    "Target cannot contain credentials"
                )
            if (
                target_url.scheme,
                target_url.host,
                target_url.port,
            ) != (
                self._base_url.scheme,
                self._base_url.host,
                self._base_url.port,
            ):
                raise RedfishInvalidTargetError(
                    "Target must use the configured Redfish origin"
                )
        except (TypeError, ValueError) as exc:
            raise RedfishInvalidTargetError("Invalid Redfish target") from exc
        return target_url

    def _request_headers(self, headers, authenticated=True):
        request_headers = CIMultiDict(
            {"Accept": "*/*", "OData-Version": "4.0"}
        )
        if headers is not None:
            request_headers.update(headers)
        if not authenticated:
            request_headers.popall("Authorization", None)
            request_headers.popall("X-Auth-Token", None)
        elif self._session_key is not None:
            request_headers.popall("Authorization", None)
            request_headers["X-Auth-Token"] = self._session_key
        elif self._authorization is not None:
            request_headers.popall("X-Auth-Token", None)
            request_headers["Authorization"] = self._authorization
        return request_headers

    async def _request(
        self,
        path,
        method="GET",
        args=None,
        body=None,
        headers=None,
        timeout=None,
        authenticated=True,
        allow_session_refresh=True,
        sensitive_body=False,
    ):
        request = AsyncRestRequest(
            path=path,
            method=method.upper(),
            body=None if sensitive_body else body,
        )
        request_timeout = (
            self._timeout if timeout is None else self._make_timeout(timeout)
        )
        kwargs = {
            "allow_redirects": False,
            "headers": self._request_headers(headers, authenticated),
            "params": args,
        }
        if request_timeout is not None:
            kwargs["timeout"] = request_timeout
        if isinstance(body, (dict, list)):
            kwargs["json"] = body
        elif body is not None:
            kwargs["data"] = body

        session_key = self._session_key
        try:
            async with self._session.request(
                method.upper(), self._resolve_url(path), **kwargs
            ) as response:
                content = await response.read()
                encoding = response.get_encoding()
                cached_response = AsyncRestResponse(
                    request=request,
                    status=response.status,
                    headers=response.headers,
                    read=content,
                    encoding=encoding,
                )
        except asyncio.TimeoutError as exc:
            raise RedfishTimeoutError("Redfish request timed out") from exc
        except aiohttp.ClientError as exc:
            raise RedfishConnectionError("Redfish request failed") from exc
        if (
            cached_response.status == 401
            and method.upper() in ("GET", "HEAD")
            and authenticated
            and allow_session_refresh
            and session_key is not None
            and self._username is not None
        ):
            if await self._refresh_session(session_key):
                return await self._request(
                    path,
                    method=method,
                    args=args,
                    body=body,
                    headers=headers,
                    timeout=timeout,
                    authenticated=authenticated,
                    allow_session_refresh=False,
                    sensitive_body=sensitive_body,
                )
        return cached_response

    async def get(self, path, args=None, headers=None, timeout=None):
        """Perform a GET request."""
        return await self._request(
            path, method="GET", args=args, headers=headers, timeout=timeout
        )

    async def head(self, path, args=None, headers=None, timeout=None):
        """Perform a HEAD request."""
        return await self._request(
            path, method="HEAD", args=args, headers=headers, timeout=timeout
        )

    async def post(
        self, path, args=None, body=None, headers=None, timeout=None
    ):
        """Perform a POST request."""
        return await self._request(
            path,
            method="POST",
            args=args,
            body=body,
            headers=headers,
            timeout=timeout,
        )

    async def put(
        self, path, args=None, body=None, headers=None, timeout=None
    ):
        """Perform a PUT request."""
        return await self._request(
            path,
            method="PUT",
            args=args,
            body=body,
            headers=headers,
            timeout=timeout,
        )

    async def patch(
        self, path, args=None, body=None, headers=None, timeout=None
    ):
        """Perform a PATCH request."""
        return await self._request(
            path,
            method="PATCH",
            args=args,
            body=body,
            headers=headers,
            timeout=timeout,
        )

    async def delete(
        self, path, args=None, headers=None, timeout=None, body=None
    ):
        """Perform a DELETE request."""
        return await self._request(
            path,
            method="DELETE",
            args=args,
            body=body,
            headers=headers,
            timeout=timeout,
        )

    @staticmethod
    def _ensure_success(response):
        password_change_uri = AsyncRedfishClient._get_password_change_uri(
            response
        )
        if password_change_uri is not False:
            raise RedfishPasswordChangeRequiredError(password_change_uri)
        if response.status in (401, 403):
            raise RedfishAuthenticationError(
                "Redfish service rejected authentication"
            )
        if not 200 <= response.status < 300:
            raise RedfishHTTPError(response)

    @staticmethod
    def _get_password_change_uri(response):
        try:
            payload = response.dict
        except RedfishProtocolError:
            return False
        if not isinstance(payload, dict):
            return False
        containers = [payload]
        if isinstance(error := payload.get("error"), dict):
            containers.append(error)
        for container in containers:
            extended_info = container.get("@Message.ExtendedInfo")
            if not isinstance(extended_info, list):
                continue
            for message in extended_info:
                if (
                    not isinstance(message, dict)
                    or not isinstance(
                        message_id := message.get("MessageId"), str
                    )
                    or not message_id.startswith("Base.")
                    or not message_id.endswith(".PasswordChangeRequired")
                ):
                    continue
                message_args = message.get("MessageArgs")
                if (
                    isinstance(message_args, list)
                    and message_args
                    and isinstance(message_args[0], str)
                ):
                    return message_args[0]
                return None
        for container in containers:
            code = container.get("code")
            if (
                isinstance(code, str)
                and code.startswith("Base.")
                and code.endswith(".PasswordChangeRequired")
            ):
                return None
        return False

    async def _get_json(self, path, authenticated=True):
        response = await self._request(
            path, method="GET", authenticated=authenticated
        )
        self._ensure_success(response)
        payload = response.dict
        if not isinstance(payload, dict):
            raise RedfishProtocolError(
                "Redfish resource at {} is not a JSON object".format(path)
            )
        return payload

    async def get_service_root(self):
        """Return the standard Redfish service root."""
        return await self._get_json(self._default_prefix)

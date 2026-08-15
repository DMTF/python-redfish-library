# Copyright Notice:
# Copyright 2016-2026 DMTF. All rights reserved.
# License: BSD 3-Clause License. For full text see link:
# https://github.com/DMTF/python-redfish-library/blob/main/LICENSE.md

"""Asynchronous Redfish client implemented with aiohttp."""

import asyncio
import base64
from dataclasses import replace

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
    RedfishUnsupportedResetError,
)
from .models import (
    get_reset_action_info_target,
    parse_computer_system,
    parse_reset_action_info,
)
from .response import AsyncRestRequest, AsyncRestResponse


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
        discovery_timeout=60,
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
        self._discovery_timeout = self._make_discovery_timeout(
            discovery_timeout
        )
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
        await self.login()
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
        if self._session_key is not None or self._authorization is not None:
            await self.logout()
        if auth == "basic":
            if ":" in self._username:
                raise ValueError(
                    "Basic authentication username cannot contain ':'"
                )
            encoded = base64.b64encode(
                "{}:{}".format(
                    self._username, self._password
                ).encode("utf-8")
            ).decode("ascii")
            self._session_key = None
            self._session_location = None
            self._authorization = "Basic {}".format(encoded)
            return

        async with self._auth_lock:
            await self._login_session()

    async def _login_session(self):
        root = await self._get_json(
            self._default_prefix, authenticated=False
        )
        links = root.get("Links")
        sessions = links.get("Sessions") if isinstance(links, dict) else None
        target = (
            sessions.get("@odata.id")
            if isinstance(sessions, dict)
            else None
        )
        if not isinstance(target, str) or not target.strip():
            target = "/redfish/v1/SessionService/Sessions"
        response = await self._request(
            target,
            method="POST",
            body={"UserName": self._username, "Password": self._password},
            authenticated=False,
            sensitive_body=True,
        )
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

    async def _refresh_session(self, expired_session_key):
        async with self._auth_lock:
            if self._session_key != expired_session_key:
                return self._session_key is not None
            self._session_key = None
            self._session_location = None
            await self._login_session()
            return True

    async def logout(self):
        """Terminate Redfish login without closing the transport."""
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

    @staticmethod
    def _make_timeout(timeout):
        if timeout is None or isinstance(timeout, aiohttp.ClientTimeout):
            return timeout
        if not isinstance(timeout, (int, float)) or timeout < 0:
            raise ValueError("Timeout must be a non-negative number")
        return aiohttp.ClientTimeout(total=timeout)

    @staticmethod
    def _make_discovery_timeout(timeout):
        if timeout is not None and (
            not isinstance(timeout, (int, float)) or timeout < 0
        ):
            raise ValueError(
                "Discovery timeout must be a non-negative number"
            )
        return timeout

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
        error = payload.get("error")
        if not isinstance(error, dict):
            return False
        code = error.get("code")
        if (
            isinstance(code, str)
            and code.startswith("Base.")
            and code.endswith(".PasswordChangeRequired")
        ):
            return None
        extended_info = error.get("@Message.ExtendedInfo")
        if not isinstance(extended_info, list):
            return False
        for message in extended_info:
            if (
                not isinstance(message, dict)
                or not isinstance(message_id := message.get("MessageId"), str)
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

    async def _get_collection_members(self, link):
        if (
            not isinstance(link, dict)
            or not isinstance(path := link.get("@odata.id"), str)
            or not path.strip()
        ):
            return []

        payloads = []
        seen_paths = set()
        while True:
            if path in seen_paths:
                raise RedfishProtocolError(
                    "Redfish collection pagination contains a cycle"
                )
            seen_paths.add(path)
            collection = await self._get_json(path)
            members = collection.get("Members")
            if not isinstance(members, list):
                return []
            for member in members:
                if (
                    isinstance(member, dict)
                    and isinstance(member_path := member.get("@odata.id"), str)
                    and member_path.strip()
                ):
                    payloads.append(await self._get_json(member_path))
            next_path = collection.get("Members@odata.nextLink")
            if not isinstance(next_path, str) or not next_path.strip():
                return payloads
            path = next_path

    async def _discover_systems(self):
        root = await self.get_service_root()
        systems = {}
        for payload in await self._get_collection_members(root.get("Systems")):
            system = parse_computer_system(payload)
            if system is None:
                continue
            action_info_target = get_reset_action_info_target(payload)
            if (
                system.reset_target is not None
                and action_info_target is not None
            ):
                action_info = await self._get_json(action_info_target)
                system = replace(
                    system,
                    reset_types=system.reset_types
                    | parse_reset_action_info(action_info),
                )
            systems[system.system_id] = system
        return systems

    async def get_systems(self):
        """Discover ComputerSystem resources from the Redfish service root."""
        try:
            return await asyncio.wait_for(
                self._discover_systems(), timeout=self._discovery_timeout
            )
        except asyncio.TimeoutError as exc:
            raise RedfishTimeoutError(
                "Redfish system discovery timed out"
            ) from exc

    async def reset_system(self, system, reset_type, timeout=None):
        """Perform a reset type advertised by a ComputerSystem."""
        if (
            system.reset_target is None
            or reset_type not in system.reset_types
        ):
            raise RedfishUnsupportedResetError(
                "ComputerSystem does not advertise ResetType {}".format(
                    reset_type
                )
            )
        response = await self.post(
            system.reset_target,
            body={"ResetType": reset_type},
            timeout=timeout,
        )
        self._ensure_success(response)
        return response

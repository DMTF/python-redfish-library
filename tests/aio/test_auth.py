# Copyright Notice:
# Copyright 2016-2026 DMTF. All rights reserved.
# License: BSD 3-Clause License. For full text see link:
# https://github.com/DMTF/python-redfish-library/blob/main/LICENSE.md

import asyncio
import json
import unittest

from multidict import CIMultiDict

from redfish.aio import (
    AsyncRedfishClient,
    RedfishAuthenticationError,
    RedfishHTTPError,
    RedfishInvalidTargetError,
    RedfishPasswordChangeRequiredError,
    RedfishProtocolError,
)


class FakeResponse:
    """Minimal aiohttp response context manager."""

    def __init__(self, status=200, headers=None, body=b"{}"):
        self.status = status
        self.headers = CIMultiDict(headers or {})
        self._body = body

    async def __aenter__(self):
        return self

    async def __aexit__(self, exc_type, exc_value, traceback):
        return None

    async def read(self):
        return self._body

    def get_encoding(self):
        return "utf-8"


class BarrierResponse(FakeResponse):
    """Response that releases after every peer has started reading."""

    def __init__(self, barrier):
        super().__init__(status=401)
        self._barrier = barrier

    async def read(self):
        self._barrier["count"] += 1
        if self._barrier["count"] == 2:
            self._barrier["event"].set()
        await self._barrier["event"].wait()
        return self._body


class ControlledResponse(FakeResponse):
    """Response controlled by test events."""

    def __init__(
        self, started, release, status=401, headers=None, body=b"{}"
    ):
        super().__init__(status=status, headers=headers, body=body)
        self._started = started
        self._release = release

    async def read(self):
        self._started.set()
        await self._release.wait()
        return self._body


class FakeSession:
    """Minimal caller-owned session for authentication tests."""

    closed = False

    def __init__(self, responses=None, response_factory=None):
        self.requests = []
        self.responses = list(responses or [])
        self.response_factory = response_factory

    def request(self, method, url, **kwargs):
        self.requests.append(
            {
                "method": method,
                "url": str(url),
                "headers": CIMultiDict(kwargs["headers"]),
                "body": kwargs.get("json", kwargs.get("data")),
            }
        )
        if self.response_factory is not None:
            return self.response_factory(method, url, kwargs)
        return self.responses.pop(0)


class TestAsyncRedfishAuthentication(unittest.IsolatedAsyncioTestCase):
    """Test asynchronous Redfish authentication."""

    async def test_credentials_require_https(self):
        """Test credentials are never sent over plain HTTP."""
        session = FakeSession()
        client = AsyncRedfishClient(
            base_url="http://bmc.example",
            username="user",
            password="password",
            session=session,
        )

        for auth in ("basic", "session"):
            with self.subTest(auth=auth), self.assertRaises(ValueError):
                await client.login(auth=auth)

        self.assertEqual(session.requests, [])

    async def test_colon_in_username_is_valid_only_for_session_auth(self):
        """Test the Basic-only username restriction is mode specific."""
        session = FakeSession(
            [
                FakeResponse(body=b"{}"),
                FakeResponse(
                    status=201,
                    headers={
                        "X-Auth-Token": "session-token",
                        "Location": "/redfish/v1/SessionService/Sessions/1",
                    },
                ),
            ]
        )
        client = AsyncRedfishClient(
            base_url="https://bmc.example",
            username="domain:user",
            password="password",
            session=session,
        )

        await client.login(auth="session")

        self.assertEqual(
            session.requests[1]["body"]["UserName"], "domain:user"
        )
        basic_client = AsyncRedfishClient(
            base_url="https://bmc.example",
            username="domain:user",
            password="password",
            session=FakeSession(),
        )
        with self.assertRaises(ValueError):
            await basic_client.login(auth="basic")

    async def test_invalid_basic_login_preserves_existing_session(self):
        """Test Basic argument validation does not terminate a session."""
        session = FakeSession([FakeResponse()])
        client = AsyncRedfishClient(
            base_url="https://bmc.example",
            username="domain:user",
            password="password",
            session=session,
            session_key="session-token",
            session_location="/redfish/v1/SessionService/Sessions/1",
        )

        with self.assertRaises(ValueError):
            await client.login(auth="basic")
        await client.get("/redfish/v1/Systems/1")

        self.assertEqual(
            [request["method"] for request in session.requests], ["GET"]
        )
        self.assertEqual(
            session.requests[0]["headers"].get("X-Auth-Token"),
            "session-token",
        )

    async def test_credentials_are_inactive_until_login(self):
        """Test constructing a client does not begin authentication."""
        session = FakeSession([FakeResponse()])
        client = AsyncRedfishClient(
            base_url="http://bmc.example",
            username="user",
            password="password",
            session=session,
        )

        await client.get("/redfish/v1/")

        self.assertIsNone(
            session.requests[0]["headers"].get("Authorization")
        )

    async def test_basic_authentication_protects_auth_headers(self):
        """Test Basic authentication cannot be replaced or duplicated."""
        session = FakeSession([FakeResponse()])
        client = AsyncRedfishClient(
            base_url="https://bmc.example",
            username="user",
            password="password",
            session=session,
        )
        await client.login(auth="basic")

        await client.get(
            "/redfish/v1/Systems",
            headers={
                "authorization": "Bearer untrusted",
                "x-auth-token": "untrusted-token",
            },
        )

        headers = session.requests[0]["headers"]
        self.assertEqual(
            headers.getall("Authorization"),
            ["Basic dXNlcjpwYXNzd29yZA=="],
        )
        self.assertIsNone(headers.get("X-Auth-Token"))

    async def test_basic_logout_clears_authentication(self):
        """Test Basic logout clears credentials without an HTTP request."""
        session = FakeSession([FakeResponse()])
        client = AsyncRedfishClient(
            base_url="https://bmc.example",
            username="user",
            password="password",
            session=session,
        )
        await client.login(auth="basic")

        await client.logout()
        await client.get("/redfish/v1/")

        self.assertEqual(len(session.requests), 1)
        self.assertIsNone(
            session.requests[0]["headers"].get("Authorization")
        )

    async def test_session_authentication_protects_auth_headers(self):
        """Test session authentication cannot be replaced or duplicated."""
        session = FakeSession([FakeResponse()])
        client = AsyncRedfishClient(
            base_url="https://bmc.example",
            session=session,
            session_key="session-token",
        )

        await client.get(
            "/redfish/v1/Systems",
            headers={
                "authorization": "Bearer untrusted",
                "x-auth-token": "untrusted-token",
            },
        )

        headers = session.requests[0]["headers"]
        self.assertIsNone(headers.get("Authorization"))
        self.assertEqual(headers.getall("X-Auth-Token"), ["session-token"])

    async def test_session_login_uses_advertised_target_and_token(self):
        """Test session authentication follows standard advertised data."""
        session = FakeSession(
            [
                FakeResponse(
                    body=(
                        b'{"Links":{"Sessions":{"@odata.id":'
                        b'"/redfish/v1/SessionService/Sessions"}}}'
                    )
                ),
                FakeResponse(
                    status=201,
                    headers={
                        "X-Auth-Token": "session-token",
                        "Location": "/redfish/v1/SessionService/Sessions/1",
                    },
                    body=(
                        b'{"@odata.id":'
                        b'"/redfish/v1/SessionService/Sessions/1"}'
                    ),
                ),
                FakeResponse(body=b'{"Id":"1"}'),
            ]
        )
        client = AsyncRedfishClient(
            base_url="https://bmc.example",
            username="user",
            password="password",
            session=session,
        )

        await client.login(auth="session")
        await client.get("/redfish/v1/Systems/1")

        self.assertEqual(
            [request["method"] for request in session.requests],
            ["GET", "POST", "GET"],
        )
        self.assertEqual(
            [request["url"] for request in session.requests],
            [
                "https://bmc.example/redfish/v1/",
                (
                    "https://bmc.example/redfish/v1/SessionService/"
                    "Sessions"
                ),
                "https://bmc.example/redfish/v1/Systems/1",
            ],
        )
        self.assertIsNone(
            session.requests[0]["headers"].get("Authorization")
        )
        self.assertIsNone(
            session.requests[1]["headers"].get("Authorization")
        )
        self.assertEqual(
            session.requests[1]["body"],
            {"UserName": "user", "Password": "password"},
        )
        self.assertEqual(
            session.requests[2]["headers"].get("X-Auth-Token"),
            "session-token",
        )
        self.assertIsNone(
            session.requests[2]["headers"].get("Authorization")
        )

    async def test_session_login_falls_back_after_root_unauthorized(self):
        """Test login tolerates a service root that incorrectly needs auth."""
        session = FakeSession(
            [
                FakeResponse(status=401),
                FakeResponse(
                    status=201,
                    headers={
                        "X-Auth-Token": "session-token",
                        "Location": (
                            "/redfish/v1/SessionService/Sessions/1"
                        ),
                    },
                ),
            ]
        )
        client = AsyncRedfishClient(
            base_url="https://bmc.example",
            username="user",
            password="password",
            session=session,
        )

        with self.assertWarnsRegex(
            UserWarning, "incorrectly responded with HTTP 401"
        ):
            await client.login()

        self.assertEqual(
            [request["method"] for request in session.requests],
            ["GET", "POST"],
        )
        self.assertTrue(
            session.requests[1]["url"].endswith(
                "/redfish/v1/SessionService/Sessions"
            )
        )

    async def test_session_login_rejects_non_object_service_root(self):
        """Test session discovery requires a service-root object."""
        session = FakeSession([FakeResponse(body=b"[]")])
        client = AsyncRedfishClient(
            base_url="https://bmc.example",
            username="user",
            password="password",
            session=session,
        )

        with self.assertRaises(RedfishProtocolError):
            await client.login()

        self.assertEqual(len(session.requests), 1)

    async def test_logout_deletes_session_without_closing_transport(self):
        """Test logout deletes only the Redfish login session."""
        session = FakeSession(
            [
                FakeResponse(
                    body=(
                        b'{"Links":{"Sessions":{"@odata.id":'
                        b'"/redfish/v1/SessionService/Sessions"}}}'
                    )
                ),
                FakeResponse(
                    status=201,
                    headers={
                        "X-Auth-Token": "session-token",
                        "Location": "/redfish/v1/SessionService/Sessions/1",
                    },
                ),
                FakeResponse(status=204, body=b""),
                FakeResponse(),
            ]
        )
        client = AsyncRedfishClient(
            base_url="https://bmc.example",
            username="user",
            password="password",
            session=session,
        )
        await client.login()

        await client.logout()
        await client.get("/redfish/v1/")

        self.assertEqual(session.requests[2]["method"], "DELETE")
        self.assertEqual(
            session.requests[2]["url"],
            "https://bmc.example/redfish/v1/SessionService/Sessions/1",
        )
        self.assertEqual(
            session.requests[2]["headers"].get("X-Auth-Token"),
            "session-token",
        )
        self.assertIsNone(
            session.requests[3]["headers"].get("X-Auth-Token")
        )
        self.assertFalse(session.closed)

    async def test_logout_accepts_already_expired_session(self):
        """Test logout succeeds when the BMC has already removed a session."""
        for status in (401, 404):
            with self.subTest(status=status):
                session = FakeSession([FakeResponse(status=status)])
                client = AsyncRedfishClient(
                    base_url="https://bmc.example",
                    session=session,
                    session_key="expired-token",
                    session_location=(
                        "/redfish/v1/SessionService/Sessions/1"
                    ),
                )

                await client.logout()

                self.assertEqual(len(session.requests), 1)

    async def test_context_manager_owns_only_redfish_session(self):
        """Test the async context manager logs in and out."""
        session = FakeSession(
            [
                FakeResponse(body=b"{}"),
                FakeResponse(
                    status=201,
                    headers={
                        "X-Auth-Token": "session-token",
                        "Location": "/redfish/v1/SessionService/Sessions/1",
                    },
                ),
                FakeResponse(status=204, body=b""),
            ]
        )
        client = AsyncRedfishClient(
            base_url="https://bmc.example",
            username="user",
            password="password",
            session=session,
        )

        async with client as entered_client:
            self.assertIs(entered_client, client)

        self.assertEqual(
            [request["method"] for request in session.requests],
            ["GET", "POST", "DELETE"],
        )
        self.assertFalse(session.closed)

    async def test_manual_relogin_terminates_previous_session(self):
        """Test an explicit second login does not leak a BMC session."""
        session = FakeSession(
            [
                FakeResponse(body=b"{}"),
                FakeResponse(
                    status=201,
                    headers={
                        "X-Auth-Token": "old-token",
                        "Location": "/redfish/v1/SessionService/Sessions/1",
                    },
                ),
                FakeResponse(status=204, body=b""),
                FakeResponse(body=b"{}"),
                FakeResponse(
                    status=201,
                    headers={
                        "X-Auth-Token": "new-token",
                        "Location": "/redfish/v1/SessionService/Sessions/2",
                    },
                ),
            ]
        )
        client = AsyncRedfishClient(
            base_url="https://bmc.example",
            username="user",
            password="password",
            session=session,
        )
        await client.login()

        await client.login()

        self.assertEqual(
            [request["method"] for request in session.requests],
            ["GET", "POST", "DELETE", "GET", "POST"],
        )
        self.assertEqual(
            session.requests[2]["headers"].get("X-Auth-Token"),
            "old-token",
        )

    async def test_concurrent_logins_do_not_leak_a_session(self):
        """Test concurrent explicit logins serialize session replacement."""
        started = asyncio.Event()
        release = asyncio.Event()
        login_count = 0

        def response_factory(method, url, kwargs):
            nonlocal login_count
            if method == "DELETE":
                return FakeResponse(status=204, body=b"")
            if method != "POST":
                return FakeResponse()
            login_count += 1
            headers = {
                "X-Auth-Token": (
                    "first-token" if login_count == 1 else "second-token"
                ),
                "Location": (
                    "/redfish/v1/SessionService/Sessions/{}".format(
                        login_count
                    )
                ),
            }
            if login_count == 1:
                return ControlledResponse(
                    started, release, status=201, headers=headers
                )
            return FakeResponse(status=201, headers=headers)

        session = FakeSession(response_factory=response_factory)
        client = AsyncRedfishClient(
            base_url="https://bmc.example",
            username="user",
            password="password",
            session=session,
        )

        first_login = asyncio.create_task(client.login())
        await started.wait()
        second_login = asyncio.create_task(client.login())
        await asyncio.sleep(0)
        release.set()
        await asyncio.gather(first_login, second_login)
        await client.get("/redfish/v1/Systems/1")

        self.assertEqual(
            [request["method"] for request in session.requests],
            ["GET", "POST", "DELETE", "GET", "POST", "GET"],
        )
        self.assertEqual(
            session.requests[-1]["headers"].get("X-Auth-Token"),
            "second-token",
        )

    async def test_logout_waits_for_login_in_progress(self):
        """Test logout cannot be undone by an in-progress login."""
        started = asyncio.Event()
        release = asyncio.Event()
        session = FakeSession(
            [
                FakeResponse(status=204, body=b""),
                FakeResponse(body=b"{}"),
                ControlledResponse(
                    started,
                    release,
                    status=201,
                    headers={
                        "X-Auth-Token": "new-token",
                        "Location": (
                            "/redfish/v1/SessionService/Sessions/2"
                        ),
                    },
                ),
                FakeResponse(status=204, body=b""),
                FakeResponse(),
            ]
        )
        client = AsyncRedfishClient(
            base_url="https://bmc.example",
            username="user",
            password="password",
            session=session,
            session_key="old-token",
            session_location="/redfish/v1/SessionService/Sessions/1",
        )

        login = asyncio.create_task(client.login())
        await started.wait()
        logout = asyncio.create_task(client.logout())
        await asyncio.sleep(0)
        self.assertFalse(logout.done())
        release.set()
        await asyncio.gather(login, logout)
        await client.get("/redfish/v1/Systems/1")

        self.assertEqual(
            [request["method"] for request in session.requests],
            ["DELETE", "GET", "POST", "DELETE", "GET"],
        )
        self.assertIsNone(
            session.requests[-1]["headers"].get("X-Auth-Token")
        )

    async def test_password_change_required_is_classified(self):
        """Test session login reports a required password change."""
        session = FakeSession(
            [
                FakeResponse(body=b"{}"),
                FakeResponse(
                    status=401,
                    body=(
                        b'{"error":{"@Message.ExtendedInfo":[{'
                        b'"MessageId":"Base.1.18.PasswordChangeRequired",'
                        b'"MessageArgs":["/redfish/v1/AccountService/'
                        b'Accounts/1"]}]}}'
                    ),
                ),
            ]
        )
        client = AsyncRedfishClient(
            base_url="https://bmc.example",
            username="user",
            password="password",
            session=session,
        )

        with self.assertRaises(
            RedfishPasswordChangeRequiredError
        ) as context:
            await client.login()

        self.assertEqual(
            context.exception.password_change_uri,
            "/redfish/v1/AccountService/Accounts/1",
        )

    async def test_successful_login_preserves_password_change_session(self):
        """Test a restricted session remains usable to change a password."""
        account_uri = "/redfish/v1/AccountService/Accounts/1"
        session = FakeSession(
            [
                FakeResponse(body=b"{}"),
                FakeResponse(
                    status=201,
                    headers={
                        "X-Auth-Token": "restricted-token",
                        "Location": (
                            "/redfish/v1/SessionService/Sessions/1"
                        ),
                    },
                    body=json.dumps(
                        {
                            "@Message.ExtendedInfo": [
                                {
                                    "MessageId": (
                                        "Base.1.18.PasswordChangeRequired"
                                    ),
                                    "MessageArgs": [account_uri],
                                }
                            ]
                        }
                    ).encode("utf-8"),
                ),
                FakeResponse(status=204, body=b""),
                FakeResponse(status=204, body=b""),
            ]
        )
        client = AsyncRedfishClient(
            base_url="https://bmc.example",
            username="user",
            password="password",
            session=session,
        )

        with self.assertRaises(
            RedfishPasswordChangeRequiredError
        ) as context:
            await client.login()
        await client.patch(account_uri, body={"Password": "new-password"})
        await client.logout()

        self.assertEqual(context.exception.password_change_uri, account_uri)
        self.assertEqual(
            session.requests[2]["headers"].get("X-Auth-Token"),
            "restricted-token",
        )
        self.assertEqual(
            session.requests[3]["headers"].get("X-Auth-Token"),
            "restricted-token",
        )

    async def test_context_manager_cleans_up_password_change_session(self):
        """Test a failed context entry does not leak a restricted session."""
        session = FakeSession(
            [
                FakeResponse(body=b"{}"),
                FakeResponse(
                    status=201,
                    headers={
                        "X-Auth-Token": "restricted-token",
                        "Location": (
                            "/redfish/v1/SessionService/Sessions/1"
                        ),
                    },
                    body=(
                        b'{"@Message.ExtendedInfo":[{'
                        b'"MessageId":'
                        b'"Base.1.18.PasswordChangeRequired",'
                        b'"MessageArgs":['
                        b'"/redfish/v1/AccountService/Accounts/1"]}]}'
                    ),
                ),
                FakeResponse(status=204, body=b""),
            ]
        )
        client = AsyncRedfishClient(
            base_url="https://bmc.example",
            username="user",
            password="password",
            session=session,
        )

        with self.assertRaises(RedfishPasswordChangeRequiredError):
            async with client:
                self.fail("Context body must not run")

        self.assertEqual(
            [request["method"] for request in session.requests],
            ["GET", "POST", "DELETE"],
        )

    async def test_password_change_code_without_uri_is_classified(self):
        """Test a password-change error does not require MessageArgs."""
        session = FakeSession(
            [
                FakeResponse(body=b"{}"),
                FakeResponse(
                    status=401,
                    body=(
                        b'{"error":{"code":'
                        b'"Base.1.18.PasswordChangeRequired"}}'
                    ),
                ),
            ]
        )
        client = AsyncRedfishClient(
            base_url="https://bmc.example",
            username="user",
            password="password",
            session=session,
        )

        with self.assertRaises(
            RedfishPasswordChangeRequiredError
        ) as context:
            await client.login()

        self.assertIsNone(context.exception.password_change_uri)

    async def test_password_change_extended_info_without_uri_is_classified(
        self,
    ):
        """Test password-change extended information can omit MessageArgs."""
        session = FakeSession(
            [
                FakeResponse(body=b"{}"),
                FakeResponse(
                    status=401,
                    body=(
                        b'{"error":{"@Message.ExtendedInfo":[{'
                        b'"MessageId":'
                        b'"Base.1.18.PasswordChangeRequired"}]}}'
                    ),
                ),
            ]
        )
        client = AsyncRedfishClient(
            base_url="https://bmc.example",
            username="user",
            password="password",
            session=session,
        )

        with self.assertRaises(
            RedfishPasswordChangeRequiredError
        ) as context:
            await client.login()

        self.assertIsNone(context.exception.password_change_uri)

    async def test_other_authentication_messages_are_not_reclassified(self):
        """Test unrelated Redfish messages remain authentication errors."""
        bodies = (
            b'{"error":{"code":"Base.1.18.GeneralError"}}',
            (
                b'{"error":{"@Message.ExtendedInfo":[{'
                b'"MessageId":"Base.1.18.GeneralError"}]}}'
            ),
        )
        for body in bodies:
            with self.subTest(body=body):
                session = FakeSession(
                    [
                        FakeResponse(body=b"{}"),
                        FakeResponse(status=401, body=body),
                    ]
                )
                client = AsyncRedfishClient(
                    base_url="https://bmc.example",
                    username="user",
                    password="password",
                    session=session,
                )

                with self.assertRaises(RedfishAuthenticationError):
                    await client.login()

    async def test_password_change_is_classified_for_basic_request(self):
        """Test Basic-authenticated operations report password changes."""
        session = FakeSession(
            [
                FakeResponse(
                    status=401,
                    body=(
                        b'{"error":{"code":'
                        b'"Base.1.18.PasswordChangeRequired"}}'
                    ),
                )
            ]
        )
        client = AsyncRedfishClient(
            base_url="https://bmc.example",
            username="user",
            password="password",
            session=session,
        )
        await client.login(auth="basic")

        with self.assertRaises(RedfishPasswordChangeRequiredError):
            await client.get_service_root()

    async def test_login_error_does_not_retain_credentials(self):
        """Test a session-creation error cannot expose its credential body."""
        session = FakeSession(
            [FakeResponse(body=b"{}"), FakeResponse(status=500)]
        )
        client = AsyncRedfishClient(
            base_url="https://bmc.example",
            username="user",
            password="password",
            session=session,
        )

        with self.assertRaises(RedfishHTTPError) as context:
            await client.login()

        self.assertIsNone(context.exception.response.request.body)

    async def test_invalid_session_credentials_are_classified(self):
        """Test a rejected session login raises an authentication error."""
        session = FakeSession(
            [FakeResponse(body=b"{}"), FakeResponse(status=401)]
        )
        client = AsyncRedfishClient(
            base_url="https://bmc.example",
            username="user",
            password="password",
            session=session,
        )

        with self.assertRaises(RedfishAuthenticationError):
            await client.login()

    async def test_malformed_session_response_is_rejected(self):
        """Test session creation requires a token and location."""
        for headers in (
            {"Location": "/redfish/v1/SessionService/Sessions/1"},
            {"X-Auth-Token": "session-token"},
        ):
            with self.subTest(headers=headers):
                session = FakeSession(
                    [
                        FakeResponse(body=b"{}"),
                        FakeResponse(status=201, headers=headers),
                    ]
                )
                client = AsyncRedfishClient(
                    base_url="https://bmc.example",
                    username="user",
                    password="password",
                    session=session,
                )

                with self.assertRaises(RedfishProtocolError):
                    await client.login()

    async def test_session_targets_must_use_configured_origin(self):
        """Test session credentials and tokens stay on their BMC origin."""
        for root, login_headers in (
            (
                {
                    "Links": {
                        "Sessions": {
                            "@odata.id": (
                                "https://attacker.example/redfish/v1/Sessions"
                            )
                        }
                    }
                },
                None,
            ),
            (
                {},
                {
                    "X-Auth-Token": "session-token",
                    "Location": (
                        "https://attacker.example/redfish/v1/Sessions/1"
                    ),
                },
            ),
        ):
            with self.subTest(root=root, login_headers=login_headers):
                responses = [
                    FakeResponse(
                        body=json.dumps(root).encode("utf-8")
                    )
                ]
                if login_headers is not None:
                    responses.append(
                        FakeResponse(status=201, headers=login_headers)
                    )
                session = FakeSession(responses)
                client = AsyncRedfishClient(
                    base_url="https://bmc.example",
                    username="user",
                    password="password",
                    session=session,
                )

                with self.assertRaises(RedfishInvalidTargetError):
                    await client.login()

    async def test_authentication_arguments_are_validated(self):
        """Test invalid authentication configuration is rejected."""
        session = FakeSession()
        invalid_constructors = (
            {"session_key": "token", "base_url": "http://bmc.example"},
            {"session_key": ""},
            {"session_key": "token", "session_location": ""},
            {"session_location": "/redfish/v1/Sessions/1"},
        )
        for arguments in invalid_constructors:
            with self.subTest(arguments=arguments), self.assertRaises(
                ValueError
            ):
                AsyncRedfishClient(
                    base_url=arguments.get(
                        "base_url", "https://bmc.example"
                    ),
                    session=session,
                    **{
                        key: value
                        for key, value in arguments.items()
                        if key != "base_url"
                    },
                )

        client = AsyncRedfishClient(
            base_url="https://bmc.example", session=session
        )
        for auth in ("session", "invalid"):
            with self.subTest(auth=auth), self.assertRaises(ValueError):
                await client.login(auth=auth)

    async def test_session_location_can_come_from_response_body(self):
        """Test a missing Location header uses the standard response link."""
        session = FakeSession(
            [
                FakeResponse(body=b"{}"),
                FakeResponse(
                    status=201,
                    headers={"X-Auth-Token": "session-token"},
                    body=(
                        b'{"@odata.id":'
                        b'"/redfish/v1/SessionService/Sessions/1"}'
                    ),
                ),
                FakeResponse(status=204, body=b""),
            ]
        )
        client = AsyncRedfishClient(
            base_url="https://bmc.example",
            username="user",
            password="password",
            session=session,
        )

        await client.login()
        await client.logout()

        self.assertEqual(
            session.requests[2]["url"],
            "https://bmc.example/redfish/v1/SessionService/Sessions/1",
        )

    async def test_existing_session_token_can_be_injected(self):
        """Test a caller can use and terminate an existing Redfish session."""
        session = FakeSession(
            [FakeResponse(), FakeResponse(status=204, body=b"")]
        )
        client = AsyncRedfishClient(
            base_url="https://bmc.example",
            session=session,
            session_key="existing-token",
            session_location="/redfish/v1/SessionService/Sessions/42",
        )

        await client.get("/redfish/v1/Systems")
        await client.logout()

        self.assertEqual(
            [
                request["headers"].get("X-Auth-Token")
                for request in session.requests
            ],
            ["existing-token", "existing-token"],
        )
        self.assertEqual(session.requests[1]["method"], "DELETE")

    async def test_expired_session_is_refreshed_for_get(self):
        """Test a failed session token is refreshed once for a safe read."""
        session = FakeSession(
            [
                FakeResponse(body=b"{}"),
                FakeResponse(
                    status=201,
                    headers={
                        "X-Auth-Token": "old-token",
                        "Location": "/redfish/v1/SessionService/Sessions/1",
                    },
                ),
                FakeResponse(status=401),
                FakeResponse(body=b"{}"),
                FakeResponse(
                    status=201,
                    headers={
                        "X-Auth-Token": "new-token",
                        "Location": "/redfish/v1/SessionService/Sessions/2",
                    },
                ),
                FakeResponse(body=b'{"Id":"1"}'),
            ]
        )
        client = AsyncRedfishClient(
            base_url="https://bmc.example",
            username="user",
            password="password",
            session=session,
        )
        await client.login()

        response = await client.get("/redfish/v1/Systems/1")

        self.assertEqual(response.status, 200)
        self.assertEqual(
            [request["method"] for request in session.requests],
            ["GET", "POST", "GET", "GET", "POST", "GET"],
        )
        self.assertEqual(
            session.requests[2]["headers"].get("X-Auth-Token"),
            "old-token",
        )
        self.assertEqual(
            session.requests[5]["headers"].get("X-Auth-Token"),
            "new-token",
        )

    async def test_session_refresh_is_attempted_only_once(self):
        """Test a second authentication failure is returned to the caller."""
        session = FakeSession(
            [
                FakeResponse(body=b"{}"),
                FakeResponse(
                    status=201,
                    headers={
                        "X-Auth-Token": "old-token",
                        "Location": "/redfish/v1/SessionService/Sessions/1",
                    },
                ),
                FakeResponse(status=401),
                FakeResponse(body=b"{}"),
                FakeResponse(
                    status=201,
                    headers={
                        "X-Auth-Token": "new-token",
                        "Location": "/redfish/v1/SessionService/Sessions/2",
                    },
                ),
                FakeResponse(status=401),
            ]
        )
        client = AsyncRedfishClient(
            base_url="https://bmc.example",
            username="user",
            password="password",
            session=session,
        )
        await client.login()

        response = await client.get("/redfish/v1/Systems/1")

        self.assertEqual(response.status, 401)
        self.assertEqual(len(session.requests), 6)

    async def test_expired_session_does_not_retry_write(self):
        """Test a failed authenticated write is never retried."""
        session = FakeSession(
            [
                FakeResponse(body=b"{}"),
                FakeResponse(
                    status=201,
                    headers={
                        "X-Auth-Token": "session-token",
                        "Location": "/redfish/v1/SessionService/Sessions/1",
                    },
                ),
                FakeResponse(status=401),
            ]
        )
        client = AsyncRedfishClient(
            base_url="https://bmc.example",
            username="user",
            password="password",
            session=session,
        )
        await client.login()

        response = await client.post(
            "/redfish/v1/Actions/Example",
            body={"Value": "example"},
        )

        self.assertEqual(response.status, 401)
        self.assertEqual(
            [request["method"] for request in session.requests],
            ["GET", "POST", "POST"],
        )

    async def test_concurrent_expiration_creates_one_new_session(self):
        """Test concurrent failed reads share one session refresh."""
        barrier = {"count": 0, "event": asyncio.Event()}
        session = FakeSession(
            [
                FakeResponse(body=b"{}"),
                FakeResponse(
                    status=201,
                    headers={
                        "X-Auth-Token": "old-token",
                        "Location": "/redfish/v1/SessionService/Sessions/1",
                    },
                ),
                BarrierResponse(barrier),
                BarrierResponse(barrier),
                FakeResponse(body=b"{}"),
                FakeResponse(
                    status=201,
                    headers={
                        "X-Auth-Token": "new-token",
                        "Location": "/redfish/v1/SessionService/Sessions/2",
                    },
                ),
                FakeResponse(),
                FakeResponse(),
            ]
        )
        client = AsyncRedfishClient(
            base_url="https://bmc.example",
            username="user",
            password="password",
            session=session,
        )
        await client.login()

        responses = await asyncio.gather(
            client.get("/redfish/v1/Systems/1"),
            client.get("/redfish/v1/Systems/2"),
        )

        self.assertEqual(
            [response.status for response in responses], [200, 200]
        )
        self.assertEqual(
            len(
                [
                    request
                    for request in session.requests
                    if request["method"] == "POST"
                    and request["url"].endswith("SessionService/Sessions")
                ]
            ),
            2,
        )

    async def test_logout_during_failed_read_does_not_reauthenticate(self):
        """Test an explicit logout wins a race with session recovery."""
        started = asyncio.Event()
        release = asyncio.Event()
        session = FakeSession(
            [
                FakeResponse(body=b"{}"),
                FakeResponse(
                    status=201,
                    headers={
                        "X-Auth-Token": "session-token",
                        "Location": "/redfish/v1/SessionService/Sessions/1",
                    },
                ),
                ControlledResponse(started, release),
                FakeResponse(status=204, body=b""),
            ]
        )
        client = AsyncRedfishClient(
            base_url="https://bmc.example",
            username="user",
            password="password",
            session=session,
        )
        await client.login()

        request = asyncio.create_task(client.get("/redfish/v1/Systems/1"))
        await started.wait()
        await client.logout()
        release.set()
        response = await request

        self.assertEqual(response.status, 401)
        self.assertEqual(
            [item["method"] for item in session.requests],
            ["GET", "POST", "GET", "DELETE"],
        )


if __name__ == "__main__":
    unittest.main()

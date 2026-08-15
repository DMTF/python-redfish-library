# Copyright Notice:
# Copyright 2016-2026 DMTF. All rights reserved.
# License: BSD 3-Clause License. For full text see link:
# https://github.com/DMTF/python-redfish-library/blob/main/LICENSE.md

import asyncio
import unittest

import aiohttp
from aiohttp import web
from aiohttp.test_utils import TestServer

from redfish.aio import (
    AsyncRedfishClient,
    RedfishConnectionError,
    RedfishInvalidTargetError,
    RedfishTimeoutError,
)


class TestAsyncRedfishClient(unittest.IsolatedAsyncioTestCase):
    """Test the asynchronous Redfish HTTP client."""

    async def asyncSetUp(self):
        self.requests = []
        app = web.Application()

        async def response(request):
            if request.path == "/slow":
                await asyncio.sleep(0.1)
            if not request.can_read_body:
                body = None
            elif request.content_type == "application/json":
                body = await request.json()
            else:
                body = await request.text()
            self.requests.append(
                {
                    "method": request.method,
                    "path_qs": request.path_qs,
                    "body": body,
                    "authorization": request.headers.get("Authorization"),
                    "authorization_all": request.headers.getall(
                        "Authorization", []
                    ),
                    "accept": request.headers.get("Accept"),
                    "odata_version": request.headers.get("OData-Version"),
                    "custom": request.headers.get("X-Custom"),
                }
            )
            if request.path == "/empty":
                return web.Response(status=204)
            status = 401 if request.path == "/unauthorized" else 200
            return web.json_response(
                {"method": request.method, "path": request.path},
                status=status,
                headers={"X-Response": "present"},
            )

        app.router.add_route("*", "/{path:.*}", response)
        self.server = TestServer(app)
        await self.server.start_server()
        self.session = aiohttp.ClientSession()
        self.client = AsyncRedfishClient(
            base_url=str(self.server.make_url("/")),
            session=self.session,
        )

    async def asyncTearDown(self):
        await self.session.close()
        await self.server.close()

    async def test_get_returns_cached_response(self):
        """Test GET query parameters and response accessors."""
        response = await self.client.get(
            "/resource",
            args={"query": "value"},
            headers={"X-Custom": "header"},
        )

        self.assertEqual(response.status, 200)
        self.assertIsInstance(response.read, bytes)
        self.assertEqual(response.dict, {"method": "GET", "path": "/resource"})
        self.assertIn(("X-Response", "present"), response.getheaders())
        self.assertEqual(response.getheader("x-response"), "present")
        self.assertEqual(response.request.method, "GET")
        self.assertEqual(response.request.path, "/resource")
        self.assertEqual(
            self.requests,
            [
                {
                    "method": "GET",
                    "path_qs": "/resource?query=value",
                    "body": None,
                    "authorization": None,
                    "authorization_all": [],
                    "accept": "*/*",
                    "odata_version": "4.0",
                    "custom": "header",
                }
            ],
        )

    async def test_headers_are_case_insensitive(self):
        """Test custom headers replace default headers case-insensitively."""
        await self.client.get(
            "/resource",
            headers={
                "accept": "application/json",
                "odata-version": "4.01",
            },
        )

        self.assertEqual(
            self.requests[0],
            {
                "method": "GET",
                "path_qs": "/resource",
                "body": None,
                "authorization": None,
                "authorization_all": [],
                "accept": "application/json",
                "odata_version": "4.01",
                "custom": None,
            },
        )

    async def test_write_methods_send_json_body(self):
        """Test POST, PUT, PATCH, and DELETE requests."""
        for method_name in ("post", "put", "patch", "delete"):
            with self.subTest(method=method_name):
                response = await getattr(self.client, method_name)(
                    "/resource",
                    args={"query": method_name},
                    body={"method": method_name},
                )
                self.assertEqual(response.status, 200)

        self.assertEqual(
            [
                (request["method"], request["body"])
                for request in self.requests
            ],
            [
                ("POST", {"method": "post"}),
                ("PUT", {"method": "put"}),
                ("PATCH", {"method": "patch"}),
                ("DELETE", {"method": "delete"}),
            ],
        )

    async def test_head_and_unstructured_body(self):
        """Test HEAD requests and unstructured request bodies."""
        response = await self.client.head("/resource")
        self.assertEqual(response.status, 200)

        await self.client.post("/resource", body="raw body")
        self.assertEqual(
            (self.requests[-1]["method"], self.requests[-1]["body"]),
            ("POST", "raw body"),
        )

    async def test_caller_owns_session(self):
        """Test the client never closes the injected session."""
        await self.client.get("/resource")

        self.assertFalse(self.session.closed)

    async def test_empty_response_has_empty_dictionary(self):
        """Test a valid empty response has an empty dictionary body."""
        response = await self.client.post("/empty")

        self.assertEqual(response.status, 204)
        self.assertEqual(response.dict, {})

    async def test_same_origin_absolute_and_scheme_relative_targets(self):
        """Test advertised same-origin target forms are accepted."""
        absolute_target = str(self.server.make_url("/absolute"))
        scheme_relative_target = str(
            self.server.make_url("/scheme-relative").with_scheme("")
        )

        await self.client.post(absolute_target)
        await self.client.post(scheme_relative_target)

        self.assertEqual(
            [request["path_qs"] for request in self.requests],
            ["/absolute", "/scheme-relative"],
        )

    def test_default_ports_share_origin(self):
        """Test explicit default ports match their implicit origins."""
        for base_url, target in (
            ("https://bmc.example", "https://bmc.example:443/reset"),
            ("http://bmc.example", "http://bmc.example:80/reset"),
        ):
            with self.subTest(base_url=base_url, target=target):
                client = AsyncRedfishClient(
                    base_url=base_url, session=self.session
                )
                self.assertEqual(client._resolve_url(target).path, "/reset")

    async def test_cross_origin_target_is_rejected_before_request(self):
        """Test credentials cannot be sent to another origin."""
        malicious_requests = []
        malicious_app = web.Application()

        async def capture_request(request):
            malicious_requests.append(request.headers.get("Authorization"))
            return web.Response(status=204)

        malicious_app.router.add_route("*", "/{path:.*}", capture_request)
        malicious_server = TestServer(malicious_app)
        await malicious_server.start_server()
        self.addAsyncCleanup(malicious_server.close)

        for target in (
            str(malicious_server.make_url("/reset")),
            str(malicious_server.make_url("/reset").with_scheme("")),
        ):
            with self.subTest(target=target), self.assertRaises(
                RedfishInvalidTargetError
            ):
                await self.client.post(target)

        self.assertEqual(malicious_requests, [])

    async def test_redirect_is_not_followed(self):
        """Test redirects cannot forward credentials to another origin."""
        malicious_requests = []
        malicious_app = web.Application()

        async def capture_request(request):
            malicious_requests.append(request.headers.get("Authorization"))
            return web.Response(status=204)

        malicious_app.router.add_get("/{path:.*}", capture_request)
        malicious_server = TestServer(malicious_app)
        await malicious_server.start_server()
        self.addAsyncCleanup(malicious_server.close)

        redirect_app = web.Application()

        async def redirect(_request):
            raise web.HTTPFound(str(malicious_server.make_url("/target")))

        redirect_app.router.add_get("/{path:.*}", redirect)
        redirect_server = TestServer(redirect_app)
        await redirect_server.start_server()
        self.addAsyncCleanup(redirect_server.close)
        redirect_client = AsyncRedfishClient(
            base_url=str(redirect_server.make_url("/")),
            session=self.session,
        )

        response = await redirect_client.get("/redirect")

        self.assertEqual(response.status, 302)
        self.assertEqual(malicious_requests, [])

    async def test_default_and_request_timeout(self):
        """Test default timeouts and per-request overrides."""
        client = AsyncRedfishClient(
            base_url=str(self.server.make_url("/")),
            session=self.session,
            timeout=0.01,
        )

        with self.assertRaises(RedfishTimeoutError):
            await client.get("/slow")

        response = await client.get("/slow", timeout=0.2)
        self.assertEqual(response.status, 200)

    async def test_connection_error_is_translated(self):
        """Test aiohttp connection failures use a Redfish exception."""
        server = TestServer(web.Application())
        await server.start_server()
        base_url = str(server.make_url("/"))
        await server.close()
        client = AsyncRedfishClient(base_url=base_url, session=self.session)

        with self.assertRaises(RedfishConnectionError):
            await client.get("/resource")

    async def test_client_validation(self):
        """Test invalid constructor arguments are rejected."""
        valid = {
            "base_url": str(self.server.make_url("/")),
            "session": self.session,
        }
        invalid_arguments = (
            {"base_url": "https://bmc.example"},
            {**valid, "username": "user"},
            {**valid, "password": "password"},
            {**valid, "timeout": -1},
            {**valid, "timeout": "invalid"},
            {**valid, "base_url": "https://["},
            {**valid, "base_url": "bmc.example"},
            {**valid, "base_url": "https://user@bmc.example"},
            {**valid, "base_url": "https://bmc.example/redfish"},
        )

        for arguments in invalid_arguments:
            with self.subTest(arguments=arguments), self.assertRaises(
                ValueError
            ):
                AsyncRedfishClient(**arguments)

    async def test_invalid_targets_are_rejected(self):
        """Test malformed and credential-bearing targets are rejected."""
        for target in (
            "https://[",
            str(self.server.make_url("/resource").with_user("other")),
        ):
            with self.subTest(target=target), self.assertRaises(
                RedfishInvalidTargetError
            ):
                await self.client.get(target)


if __name__ == "__main__":
    unittest.main()

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
    ComputerSystem,
    RedfishAuthenticationError,
    RedfishHTTPError,
    RedfishProtocolError,
    RedfishTimeoutError,
    RedfishUnsupportedResetError,
)


class TestAsyncComputerSystemDiscovery(unittest.IsolatedAsyncioTestCase):
    """Test standard asynchronous ComputerSystem operations."""

    async def asyncSetUp(self):
        self.requests = []
        self.statuses = {}
        self.delays = {}
        self.raw_responses = {}
        self.resources = {
            "/redfish/v1/": {
                "Systems": {"@odata.id": "/redfish/v1/Systems"},
            },
            "/redfish/v1/Systems": {
                "Members": [{"@odata.id": "/redfish/v1/Systems/1"}],
                "Members@odata.nextLink": "/redfish/v1/Systems?page=2",
            },
            "/redfish/v1/Systems?page=2": {
                "Members": [{"@odata.id": "/redfish/v1/Systems/2"}],
            },
            "/redfish/v1/Systems/1": {
                "@odata.id": "/redfish/v1/Systems/1",
                "Id": "1",
                "Name": "Server One",
                "UUID": "uuid-1",
                "Manufacturer": "Acme",
                "Model": "Model 1",
                "SerialNumber": "serial-1",
                "PowerState": "On",
                "Actions": {
                    "#ComputerSystem.Reset": {
                        "target": (
                            "/redfish/v1/Systems/1/Actions/"
                            "ComputerSystem.Reset"
                        ),
                        "ResetType@Redfish.AllowableValues": [
                            "On",
                            "GracefulShutdown",
                            "VendorReset",
                            1,
                        ],
                    }
                },
            },
            "/redfish/v1/Systems/2": {
                "@odata.id": "/redfish/v1/Systems/2",
                "Id": "2",
                "Name": "Server Two",
                "PowerState": "Off",
                "Actions": {
                    "#ComputerSystem.Reset": {
                        "target": (
                            "/redfish/v1/Systems/2/Actions/"
                            "ComputerSystem.Reset"
                        ),
                        "@Redfish.ActionInfo": (
                            "/redfish/v1/Systems/2/ResetActionInfo"
                        ),
                    }
                },
            },
            "/redfish/v1/Systems/2/ResetActionInfo": {
                "Parameters": [
                    {
                        "Name": "ResetType",
                        "AllowableValues": [
                            "ForceOff",
                            "GracefulRestart",
                            "VendorReset",
                        ],
                    }
                ]
            },
        }
        app = web.Application()

        async def response(request):
            path = request.path_qs
            if delay := self.delays.get(path):
                await asyncio.sleep(delay)
            body = await request.json() if request.can_read_body else None
            self.requests.append((request.method, path, body))
            status = self.statuses.get(path, 200)
            if path in self.raw_responses:
                return web.Response(
                    text=self.raw_responses[path],
                    status=status,
                    content_type="application/json",
                )
            if request.method != "GET":
                return web.Response(status=status)
            return web.json_response(
                self.resources.get(path, {}), status=status
            )

        app.router.add_route("*", "/{path:.*}", response)
        self.server = TestServer(app)
        await self.server.start_server()
        self.session = aiohttp.ClientSession()
        self.client = AsyncRedfishClient(
            base_url=str(self.server.make_url("/")),
            username="user",
            password="password",
            session=self.session,
        )

    async def asyncTearDown(self):
        await self.session.close()
        await self.server.close()

    async def test_discovers_paginated_systems_and_metadata(self):
        """Test service-root traversal and ComputerSystem parsing."""
        systems = await self.client.get_systems()

        self.assertEqual(
            systems,
            {
                "1": ComputerSystem(
                    odata_id="/redfish/v1/Systems/1",
                    system_id="1",
                    name="Server One",
                    uuid="uuid-1",
                    manufacturer="Acme",
                    model="Model 1",
                    serial_number="serial-1",
                    power_state="On",
                    reset_target=(
                        "/redfish/v1/Systems/1/Actions/"
                        "ComputerSystem.Reset"
                    ),
                    reset_types=frozenset({"On", "GracefulShutdown"}),
                ),
                "2": ComputerSystem(
                    odata_id="/redfish/v1/Systems/2",
                    system_id="2",
                    name="Server Two",
                    uuid=None,
                    manufacturer=None,
                    model=None,
                    serial_number=None,
                    power_state="Off",
                    reset_target=(
                        "/redfish/v1/Systems/2/Actions/"
                        "ComputerSystem.Reset"
                    ),
                    reset_types=frozenset({"ForceOff", "GracefulRestart"}),
                ),
            },
        )
        self.assertEqual(
            [request[1] for request in self.requests],
            [
                "/redfish/v1/",
                "/redfish/v1/Systems",
                "/redfish/v1/Systems/1",
                "/redfish/v1/Systems?page=2",
                "/redfish/v1/Systems/2",
                "/redfish/v1/Systems/2/ResetActionInfo",
            ],
        )

    async def test_reset_system_uses_advertised_target_and_type(self):
        """Test reset uses the target and ResetType advertised by the BMC."""
        system = (await self.client.get_systems())["2"]
        self.requests.clear()

        response = await self.client.reset_system(system, "ForceOff")

        self.assertEqual(response.status, 200)
        self.assertEqual(
            self.requests,
            [
                (
                    "POST",
                    "/redfish/v1/Systems/2/Actions/ComputerSystem.Reset",
                    {"ResetType": "ForceOff"},
                )
            ],
        )

    async def test_reset_system_rejects_unadvertised_type(self):
        """Test an unadvertised reset type never reaches the BMC."""
        system = (await self.client.get_systems())["2"]
        self.requests.clear()

        with self.assertRaises(RedfishUnsupportedResetError):
            await self.client.reset_system(system, "On")

        self.assertEqual(self.requests, [])

    async def test_missing_and_malformed_systems_are_skipped(self):
        """Test unusable collection and ComputerSystem data is skipped."""
        self.resources["/redfish/v1/Systems"] = {
            "Members": [
                {},
                {"@odata.id": 1},
                {"@odata.id": " "},
                {"@odata.id": "/redfish/v1/Systems/malformed"},
            ]
        }
        self.resources["/redfish/v1/Systems/malformed"] = {
            "@odata.id": "/redfish/v1/Systems/malformed"
        }

        self.assertEqual(await self.client.get_systems(), {})

        self.resources["/redfish/v1/"] = {}
        self.assertEqual(await self.client.get_systems(), {})

    async def test_repeated_pagination_link_is_rejected(self):
        """Test cyclic collection pagination is rejected."""
        self.resources["/redfish/v1/Systems"] = {
            "Members": [],
            "Members@odata.nextLink": "/redfish/v1/Systems",
        }

        with self.assertRaises(RedfishProtocolError):
            await self.client.get_systems()

    async def test_discovery_timeout_includes_action_info(self):
        """Test the overall discovery deadline includes ActionInfo requests."""
        self.delays["/redfish/v1/Systems/2/ResetActionInfo"] = 0.1
        client = AsyncRedfishClient(
            base_url=str(self.server.make_url("/")),
            username="user",
            password="password",
            session=self.session,
            discovery_timeout=0.01,
        )

        with self.assertRaises(RedfishTimeoutError):
            await client.get_systems()

    async def test_discovery_classifies_http_errors(self):
        """Test unsuccessful responses are classified."""
        for status, expected_error in (
            (401, RedfishAuthenticationError),
            (403, RedfishAuthenticationError),
            (500, RedfishHTTPError),
        ):
            with self.subTest(status=status):
                self.statuses["/redfish/v1/"] = status
                with self.assertRaises(expected_error):
                    await self.client.get_systems()

    async def test_discovery_rejects_malformed_json(self):
        """Test malformed JSON is reported as a protocol error."""
        self.raw_responses["/redfish/v1/"] = "{"

        with self.assertRaises(RedfishProtocolError):
            await self.client.get_systems()

    async def test_discovery_rejects_non_object_json(self):
        """Test a Redfish resource must contain a JSON object."""
        self.raw_responses["/redfish/v1/"] = "[]"

        with self.assertRaises(RedfishProtocolError):
            await self.client.get_systems()

    async def test_malformed_collection_members_are_ignored(self):
        """Test a collection without a Members array is treated as empty."""
        self.resources["/redfish/v1/Systems"] = {"Members": {}}

        self.assertEqual(await self.client.get_systems(), {})

    async def test_reset_system_classifies_http_errors(self):
        """Test reset HTTP failures are classified."""
        system = (await self.client.get_systems())["1"]
        target = "/redfish/v1/Systems/1/Actions/ComputerSystem.Reset"

        for status, expected_error in (
            (401, RedfishAuthenticationError),
            (500, RedfishHTTPError),
        ):
            with self.subTest(status=status):
                self.statuses[target] = status
                with self.assertRaises(expected_error):
                    await self.client.reset_system(system, "On")


if __name__ == "__main__":
    unittest.main()

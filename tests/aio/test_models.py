# Copyright Notice:
# Copyright 2016-2026 DMTF. All rights reserved.
# License: BSD 3-Clause License. For full text see link:
# https://github.com/DMTF/python-redfish-library/blob/main/LICENSE.md

import unittest

from redfish.aio import (
    get_reset_action_info_target,
    parse_computer_system,
    parse_reset_action_info,
)


class TestAsyncResourceModels(unittest.TestCase):
    """Test standard resource parsing used by the asynchronous client."""

    def test_action_info_requires_reset_action(self):
        """Test ActionInfo lookup without a reset action."""
        self.assertIsNone(get_reset_action_info_target({}))

    def test_action_info_without_usable_reset_values(self):
        """Test malformed ActionInfo parameters produce no reset types."""
        for payload in (
            {},
            {"Parameters": [None, {"Name": "OtherParameter"}]},
            {"Parameters": [{"Name": "ResetType"}]},
        ):
            with self.subTest(payload=payload):
                self.assertEqual(parse_reset_action_info(payload), frozenset())

    def test_advertised_reset_types_are_forward_compatible(self):
        """Test unknown string values remain available to callers."""
        self.assertEqual(
            parse_reset_action_info(
                {
                    "Parameters": [
                        {
                            "Name": "ResetType",
                            "AllowableValues": [
                                "On",
                                "FutureStandardReset",
                                " ",
                                1,
                            ],
                        }
                    ]
                }
            ),
            frozenset({"On", "FutureStandardReset"}),
        )
        system = parse_computer_system(
            {
                "@odata.id": "/redfish/v1/Systems/1",
                "Id": "1",
                "Actions": {
                    "#ComputerSystem.Reset": {
                        "target": "/redfish/v1/Systems/1/Actions/Reset",
                        "ResetType@Redfish.AllowableValues": [
                            "On",
                            "FutureStandardReset",
                            " ",
                            1,
                        ],
                    }
                },
            }
        )
        self.assertIsNotNone(system)
        self.assertEqual(
            system.reset_types,
            frozenset({"On", "FutureStandardReset"}),
        )

    def test_computer_system_requires_standard_identifiers(self):
        """Test systems without usable identifiers are rejected."""
        for payload in (
            {},
            {"Id": "1"},
            {"@odata.id": "/redfish/v1/Systems/1"},
            {"@odata.id": " ", "Id": "1"},
            {"@odata.id": "/redfish/v1/Systems/1", "Id": 1},
        ):
            with self.subTest(payload=payload):
                self.assertIsNone(parse_computer_system(payload))

    def test_computer_system_without_reset_action(self):
        """Test a usable system need not advertise reset support."""
        system = parse_computer_system(
            {"@odata.id": "/redfish/v1/Systems/1", "Id": "1"}
        )

        self.assertIsNotNone(system)
        self.assertIsNone(system.reset_target)
        self.assertEqual(system.reset_types, frozenset())


if __name__ == "__main__":
    unittest.main()

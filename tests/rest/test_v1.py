# Copyright Notice:
# Copyright 2016-2021 DMTF. All rights reserved.
# License: BSD 3-Clause License. For full text see link:
# https://github.com/DMTF/python-redfish-library/blob/main/LICENSE.md

# -*- encoding: utf-8 -*-
import json
import unittest
from unittest import mock

from redfish.rest.v1 import HttpClient, RetriesExhaustedError, redfish_client


class TestRedFishClient(unittest.TestCase):
    def setUp(self) -> None:
        self.base_url = "http://foo.bar"
        self.username = "rstallman"
        self.password = "123456"
        self.default_prefix = "/custom/redfish/v1/"
        self.sessionkey = "fg687glgkf56vlgkf"
        self.capath = "/path/to/the/dir"
        self.cafile = "filename.test"
        self.timeout = 666
        self.max_retry = 42

    def test_redfish_client(self) -> None:
        # NOTE(hberaud) the client try to connect when we initialize the
        # http client object so we need to catch the retries exception first.
        # In a second time we need to mock the six.http_client to simulate
        # server responses and do some other tests
        with self.assertRaises(RetriesExhaustedError):
            client = redfish_client(base_url=self.base_url)
            # Check the object type
            self.assertTrue(isinstance(client, HttpClient))
            # Check the object attributes values.
            # Here we check if the client object is properly initialized
            self.assertEqual(client.base_url, self.base_url)
            self.assertEqual(client.username, self.username)
            self.assertEqual(client.password, self.password)
            self.assertEqual(client.default_prefix, self.default_prefix)
            self.assertEqual(client.sessionkey, self.sessionkey)
            self.assertEqual(client.capath, self.capath)
            self.assertEqual(client.cafile, self.cafile)
            self.assertEqual(client.timeout, self.timeout)
            self.assertEqual(client.max_retry, self.max_retry)

    def test_redfish_client_no_root_resp(self) -> None:
        client = redfish_client(base_url=self.base_url, check_connectivity=False)
        self.assertIsNone(getattr(client, "root_resp", None))

    @mock.patch("requests.Session.request")
    def test_redfish_client_root_object_initialized_after_login(
        self, mocked_request: mock.Mock
    ) -> None:
        dummy_root_data = '{"Links": {"Sessions": {"@data.id": "/redfish/v1/SessionService/Sessions"}}}'
        dummy_session_response = (
            '{"@odata.type": "#Session.v1_1_2.Session", '
            '"@odata.id": "/redfish/v1/SessionService/Sessions/1", '
            '"Id": "1", "Name": "User Session", "Description": "Manager User Session", '
            '"UserName": "user", "Oem": {}}'
        )
        root_resp = mock.Mock(content=dummy_root_data, status_code=200)
        auth_resp = mock.Mock(
            content=dummy_session_response,
            status_code=200,
            headers={"location": "fake", "x-auth-token": "fake"},
        )
        mocked_request.side_effect = [
            root_resp,
            auth_resp,
        ]
        client = redfish_client(base_url=self.base_url, check_connectivity=False)
        client.login()

        self.assertEqual(client.root, json.loads(dummy_root_data))

    @mock.patch("requests.Session.request")
    def test_basic_auth_emits_warning(self, mocked_request: mock.Mock) -> None:
        """Test that using basic auth emits a security warning."""
        import warnings
        from redfish.rest.v1 import AuthMethod

        dummy_root_data = '{"Links": {"Sessions": {"@data.id": "/redfish/v1/SessionService/Sessions"}}}'
        root_resp = mock.Mock(content=dummy_root_data, status_code=200)
        auth_resp = mock.Mock(content="", status_code=200)
        mocked_request.side_effect = [
            root_resp,
            auth_resp,
        ]
        client = redfish_client(base_url=self.base_url, check_connectivity=False)
        
        with warnings.catch_warnings(record=True) as w:
            warnings.simplefilter("always")
            client.login(username=self.username, password=self.password, auth=AuthMethod.BASIC)
            
            # Check that a warning was emitted
            self.assertEqual(len(w), 1)
            self.assertTrue(issubclass(w[0].category, UserWarning))
            # Check that the warning contains the expected keywords
            warning_message = str(w[0].message)
            self.assertIn("HTTP Basic authentication", warning_message)
            self.assertIn("security concerns", warning_message)
            self.assertIn("RFC7617", warning_message)
            self.assertIn("session management", warning_message)


if __name__ == "__main__":
    unittest.main()

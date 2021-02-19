# Copyright Notice:
# Copyright 2016-2021 DMTF. All rights reserved.
# License: BSD 3-Clause License. For full text see link:
# https://github.com/DMTF/python-redfish-library/blob/master/LICENSE.md

# -*- encoding: utf-8 -*-
import unittest

from redfish.rest.v1 import HttpClient
from redfish.rest.v1 import RetriesExhaustedError
from redfish.rest.v1 import redfish_client


class TestRedFishClient(unittest.TestCase):
    def test_redfish_client(self):
        base_url = "http://foo.bar"
        username = "rstallman"
        password = "123456"
        default_prefix = "/custom/redfish/v1/"
        sessionkey = "fg687glgkf56vlgkf"
        capath = "/path/to/the/dir"
        cafile = "filename.test"
        timeout = 666
        max_retry = 42
        # NOTE(hberaud) the client try to connect when we initialize the
        # http client object so we need to catch the retries exception first.
        # In a second time we need to mock the six.http_client to simulate
        # server responses and do some other tests
        with self.assertRaises(RetriesExhaustedError):
            client = redfish_client(base_url=base_url)
            # Check the object type
            self.assertTrue(isinstance(client, HttpClient))
            # Check the object attributes values.
            # Here we check if the client object is properly initialized
            self.assertEqual(client.base_url, base_url)
            self.assertEqual(client.username, username)
            self.assertEqual(client.password, password)
            self.assertEqual(client.default_prefix, default_prefix)
            self.assertEqual(client.sessionkey, sessionkey)
            self.assertEqual(client.capath, capath)
            self.assertEqual(client.cafile, cafile)
            self.assertEqual(client.timeout, timeout)
            self.assertEqual(client.max_retry, max_retry)

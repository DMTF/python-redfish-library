# -*- encoding: utf-8 -*-
import unittest

from redfish.discovery.discovery import FakeSocket
from redfish.discovery.discovery import sanitize

from six import BytesIO


class TestFakeSocket(unittest.TestCase):
    def test_init(self):
        fake = FakeSocket(b"foo")
        self.assertTrue(isinstance(fake, FakeSocket))
        self.assertTrue(isinstance(fake._file, BytesIO))


class TestDiscover(unittest.TestCase):
    def test_sanitize(self):
        self.assertEqual(sanitize(257, 1, 255), 255)
        self.assertEqual(sanitize(0, 1, 255), 1)
        self.assertEqual(sanitize(0, 1), 1)
        self.assertEqual(sanitize(2000, 1), 2000)
        self.assertEqual(sanitize(-1, 1), 1)

# -*- encoding: utf-8 -*-
import unittest

from redfish.ris import RisMonolithMember_v1_0_0
from redfish.ris import RisMonolithMemberBase
from redfish.ris.sharedtypes import Dictable


class TestRisMonolithMemberBase(unittest.TestCase):
    def test_init(self):
        RisMonolithMemberBase()
        self.assertTrue(issubclass(
            RisMonolithMemberBase,
            Dictable
        ))


class TestRisMonolithMember_v1_0_0(unittest.TestCase):
    def test_init(self):
        with self.assertRaises(TypeError):
            RisMonolithMember_v1_0_0()

        RisMonolithMember_v1_0_0("test")
        self.assertTrue(issubclass(
            RisMonolithMember_v1_0_0,
            RisMonolithMemberBase
        ))
        self.assertTrue(issubclass(
            RisMonolithMember_v1_0_0,
            Dictable
        ))

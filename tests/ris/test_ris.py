# Copyright Notice:
# Copyright 2016-2021 DMTF. All rights reserved.
# License: BSD 3-Clause License. For full text see link:
# https://github.com/DMTF/python-redfish-library/blob/main/LICENSE.md

# -*- encoding: utf-8 -*-
import unittest

from redfish.ris import RisMonolithMember_v1_0_0
from redfish.ris import RisMonolithMemberBase
from redfish.ris.sharedtypes import Dictable


class TestRisMonolithMemberBase(unittest.TestCase):
    def test_init(self):
        RisMonolithMemberBase()
        self.assertTrue(issubclass(RisMonolithMemberBase, Dictable))


class TestRisMonolithMember_v1_0_0(unittest.TestCase):
    def test_init(self):
        with self.assertRaises(TypeError):
            RisMonolithMember_v1_0_0()

        RisMonolithMember_v1_0_0("test")
        self.assertTrue(
            issubclass(RisMonolithMember_v1_0_0, RisMonolithMemberBase)
        )
        self.assertTrue(issubclass(RisMonolithMember_v1_0_0, Dictable))

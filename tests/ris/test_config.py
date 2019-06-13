# -*- encoding: utf-8 -*-
import os
import tempfile
import textwrap
import unittest

from redfish.ris.config import AutoConfigParser


CONFIG = textwrap.dedent("""
    [DEFAULT]
    ServerAliveInterval = 45
    Compression = yes
    CompressionLevel = 9
    ForwardX11 = yes
    
    [bitbucket.org]
    User = hg
    
    [topsecret.server.com]
    Port = 50022
    ForwardX11 = no
""")


class TestAutoConfigParser(unittest.TestCase):
    def test_init(self):
        acp = AutoConfigParser()
        self.assertEqual(acp._configfile, None)
        with tempfile.TemporaryDirectory() as tmpdirname:
            cfgfile = "{tmpdir}/config.ini".format(tmpdir=tmpdirname)
            with open(cfgfile, "w+") as config:
                config.write(CONFIG)
            acp = AutoConfigParser(cfgfile)
            self.assertEqual(acp._configfile, cfgfile)

    def test_load(self):
        with tempfile.TemporaryDirectory() as tmpdirname:
            cfgfile = "{tmpdir}/config.ini".format(tmpdir=tmpdirname)
            with open(cfgfile, "w+") as config:
                config.write(CONFIG)
            acp = AutoConfigParser()
            acp.load(cfgfile)

    def test_save(self):
        with tempfile.TemporaryDirectory() as tmpdirname:
            cfgfile = "{tmpdir}/config.ini".format(tmpdir=tmpdirname)
            with open(cfgfile, "w+") as config:
                config.write(CONFIG)
            acp = AutoConfigParser(cfgfile)
            acp.load()
            acp.save()
            dump = "{tmpdir}/config2.ini".format(tmpdir=tmpdirname)
            acp.save(dump)

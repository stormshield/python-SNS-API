#!/usr/bin/python
# -*- coding: utf-8 -*-

from __future__ import unicode_literals
import os
import sys
import unittest

from stormshield.sns.sslclient import SSLClient

APPLIANCE = os.getenv('APPLIANCE', "")
PASSWORD = os.getenv('PASSWORD', "")

@unittest.skipIf(APPLIANCE=="", "APPLIANCE env var must be set to the ip/hostname of a running SNS appliance")
@unittest.skipIf(PASSWORD=="", "PASSWORD env var must be set to the firewall password")
class TestUtf8(unittest.TestCase):
    """ Test INI format """

    def setUp(self):
        self.client = SSLClient(host=APPLIANCE, user='admin', password=PASSWORD, sslverifyhost=False)
        self.client.send_command('CONFIG OBJECT HOST NEW type=host name=hostutf8 ip=1.2.3.4 comment="comment with utf8 characters éè\u2713"')

        self.maxDiff = 5000

    def tearDown(self):
        self.client.send_command('CONFIG OBJECT HOST delete name=hostutf8')
        self.client.disconnect()

    def test_utf8(self):
        """ send and receive utf-8 content """

        expected = """101 code=00a01000 msg="Begin" format="section_line"
[Object]
type=host global=0 name=hostutf8 ip=1.2.3.4 modify=1 comment="comment with utf8 characters éè\u2713" type=host
100 code=00a00100 msg="Ok\""""

        response = self.client.send_command('CONFIG OBJECT LIST type=host search=hostutf8 start=0')

        self.assertEqual(response.output, expected)
        self.assertEqual(response.ret, 100)


if __name__ == '__main__':
    unittest.main()

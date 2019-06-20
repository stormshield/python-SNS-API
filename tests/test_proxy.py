#!/usr/bin/python

import os
import unittest
from stormshield.sns.sslclient import SSLClient

APPLIANCE = os.getenv('APPLIANCE', "")
PASSWORD = os.getenv('PASSWORD', "")
PROXY = os.getenv('PROXY', "")

@unittest.skipIf(APPLIANCE=="", "APPLIANCE env var must be set to the ip/hostname of a running SNS appliance")
@unittest.skipIf(PASSWORD=="", "PASSWORD env var must be set to the firewall password")
@unittest.skipIf(PROXY=="", "PROXY env var must be set to proxy url")
class TestProxy(unittest.TestCase):
    """ Test proxy option """

    def test_sslverifyhost(self):
        """ Test proxy option """

        try:
            client = SSLClient(host=APPLIANCE, user='admin', password=PASSWORD, sslverifypeer=False, proxy=PROXY)
            self.assertTrue(1==1, "SSLClient connects with proxy")
        except:
            self.fail("SSLClient did not connect")

        response = client.send_command('LIST')
        self.assertEqual(response.ret, 100)

        client.disconnect()

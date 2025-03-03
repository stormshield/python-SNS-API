#!/usr/bin/python

import os
import unittest
from stormshield.sns.sslclient import SSLClient

APPLIANCE = os.getenv('APPLIANCE', "")
SERIAL = os.getenv('SERIAL', "")
PASSWORD = os.getenv('PASSWORD', "")
SSLVERIFYPEER = os.getenv('SSLVERIFYPEER', "1") == "1";

@unittest.skipIf(APPLIANCE=="", "APPLIANCE env var must be set to the ip/hostname of a running SNS appliance")
@unittest.skipIf(SERIAL=="", "SERIAL env var must be set to the firewall serial number")
@unittest.skipIf(PASSWORD=="", "PASSWORD env var must be set to the firewall password")
class TestAuth(unittest.TestCase):
    """ Test authentication options """

    def test_sslverifyhost(self):
        """ Test sslverifyhost option """

        try:
            client = SSLClient(host=SERIAL, ip=APPLIANCE, user='admin', password=PASSWORD, sslverifyhost=True, sslverifypeer=SSLVERIFYPEER)
            self.assertTrue(1==1, "SSLClient connects with sslverifyhost=True")
        except:
            self.fail("SSLClient did not connect")
        
        response = client.send_command('LIST')
        self.assertEqual(response.ret, 100)

        client.disconnect()

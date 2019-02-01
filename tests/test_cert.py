#!/usr/bin/python

import os
import unittest
from stormshield.sns.sslclient import SSLClient

APPLIANCE=os.getenv('APPLIANCE', "")
FQDN = os.getenv('FQDN', "")
PASSWORD = os.getenv('PASSWORD', "")
CABUNDLE = os.getenv('CABUNDLE', "")
CERT = os.getenv('CERT', "")

@unittest.skipIf(APPLIANCE=="", "APPLIANCE env var must be set to the ip/hostname of a running SNS appliance")
@unittest.skipIf(FQDN=="", "FQDN env var must be set to the firewall fqdn")
@unittest.skipIf(PASSWORD=="", "PASSWORD env var must be set to the firewall password")
@unittest.skipIf(CABUNDLE=="", "CABUNDLE env var must be set to the CA bundle file")
@unittest.skipIf(CERT=="", "CERT env var must be set to the certificate file")
class TestCert(unittest.TestCase):
    """ Test cabundle / certificate authentication options """

    def test_sslverifypeer(self):
        """ Test sslverifypeer option """

        # by default sslverifypeer is True
        try:
            client = SSLClient(host=APPLIANCE, user='admin', password=PASSWORD)
            self.fail("SSLClient should have failed (untrusted CA)")
        except Exception as exception:
            self.assertTrue(1==1, "SSLClient did not connect (untrusted CA)")
        
        try:
            client = SSLClient(host=APPLIANCE, user='admin', password=PASSWORD, sslverifypeer=False)
            self.assertTrue(1==1, "SSLClient connects with sslverifypeer=True")
        except Exception as exception:
            print(exception)
            self.fail("SSLClient did not connect")

        response = client.send_command('LIST')
        self.assertEqual(response.ret, 100)

        client.disconnect()

    def test_cabundle(self):
        """ Test cabundle option """

        try:
            client = SSLClient(host=FQDN, ip=APPLIANCE, user='admin', password=PASSWORD, sslverifyhost=True, cabundle=CABUNDLE)
            self.assertTrue(1==1, "SSLClient connects with cabundle")
        except Exception as exception:
            print(exception)
            self.fail("SSLClient did not connect")
        
        response = client.send_command('LIST')
        self.assertEqual(response.ret, 100)

        client.disconnect()

    def test_cert(self):
        """ Test user certificate authentication  """

        try:
            client = SSLClient(host=FQDN, ip=APPLIANCE, usercert=CERT, sslverifyhost=True, cabundle=CABUNDLE)
            self.assertTrue(1==1, "SSLClient connects with cabundle")
        except Exception as exception:
            print(exception)
            self.fail("SSLClient did not connect")
        
        response = client.send_command('LIST')
        self.assertEqual(response.ret, 100)

        client.disconnect()

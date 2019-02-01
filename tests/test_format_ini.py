#!/usr/bin/python

import os
import sys
import unittest

from stormshield.sns.sslclient import SSLClient

APPLIANCE=os.getenv('APPLIANCE', "")
PASSWORD = os.getenv('PASSWORD', "")

@unittest.skipIf(APPLIANCE=="", "APPLIANCE env var must be set to the ip/hostname of a running SNS appliance")
@unittest.skipIf(PASSWORD=="", "PASSWORD env var must be set to the firewall password")
class TestFormatIni(unittest.TestCase):
    """ Test INI format """

    def setUp(self):
        self.client = SSLClient(host=APPLIANCE, user='admin', password=PASSWORD, sslverifyhost=False)

        self.maxDiff = 5000

    def tearDown(self):
        self.client.disconnect()

    def test_raw(self):
        """ raw format """

        expected = """101 code=00a01000 msg="Begin" format="raw"
AUTH       : User authentication
CHPWD      : Return if it's necessary to update password or not
CONFIG     : Firewall configuration functions
GLOBALADMIN : Global administration
HA         : HA functions
HELP       : Display available commands
LIST       : Display the list of connected users, show user rights (Level) and rights for current session (SessionLevel).
LOG        : Log related functions.Everywhere a timezone is needed, if not specified the command is treated with firewall timezone setting.
MODIFY     : Get / lose the modify or the mon_write right
MONITOR    : Monitor related functions
NOP        : Do nothing but avoid disconnection from server.
PKI        : show or update the pki
QUIT       : Log off
REPORT     : Handling of reports
SYSTEM     : System commands
USER       : User related functions
VERSION    : Display server version
100 code=00a00100 msg="Ok\""""

        response = self.client.send_command('HELP')

        self.assertEqual(response.output, expected)
        self.assertEqual(response.ret, 100)

    def test_section(self):
        """ section format """
        
        expected = """101 code=00a01000 msg="Begin" format="section"
[Global]
State=0
RiskHalfLife=21600
RiskTTL=86400
[Alarm]
Minor=2
Major=10
[Sandboxing]
Suspicious=2
Malicious=50
Failed=0
[Antivirus]
Infected=100
Unknown=2
Failed=0
100 code=00a00100 msg="Ok\""""

        response = self.client.send_command('CONFIG HOSTREP SHOW')

        self.assertEqual(response.output, expected)
        self.assertEqual(response.ret, 100)

    def test_section_line(self):
        """ section_line format """

        expected="""101 code=00a01000 msg="Begin" format="section_line"
[Result]
id=pvm_detailed type=pvm name="Detailed Vulnerability Mail"
id=pvm_summary type=pvm name="Summary Vulnerability Mail"
id=app_cert_req type=cert_req name="Accept the certificate request"
id=rej_cert_req type=cert_req name="Reject the certificate request"
id=app_user_req type=user_req name="Accept the user request"
id=rej_user_req type=user_req name="Reject the user request"
id=sponsor_req type=sponsoring name="Sponsoring request"
id=smtp_test_msg type=smtp_conf name="Test SMTP configuration"
100 code=00a00100 msg="Ok\""""

        response = self.client.send_command('CONFIG COMMUNICATION EMAIL TEMPLATE LIST')

        self.assertEqual(response.output, expected)
        self.assertEqual(response.ret, 100)

    def test_list(self):
        """ list format """

        expected = """101 code=00a01000 msg="Begin" format="list"
[Result]
labo_network
Network_internals
100 code=00a00100 msg="Ok\""""

        response = self.client.send_command('CONFIG WEBADMIN ACCESS SHOW')

        self.assertEqual(response.output, expected)
        self.assertEqual(response.ret, 100)

if __name__ == '__main__':
    unittest.main()

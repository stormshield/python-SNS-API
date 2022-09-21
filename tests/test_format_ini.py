#!/usr/bin/python

import os
import sys
import unittest
import re

from stormshield.sns.sslclient import SSLClient

APPLIANCE = os.getenv('APPLIANCE', "")
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

        expected_re = """101 code=00a01000 msg="Begin" format="raw"
AUTH.*
CHPWD.*
100 code=00a00100 msg="Ok\""""

        response = self.client.send_command('HELP')

        self.assertTrue(re.match(expected_re, response.output, re.MULTILINE|re.DOTALL))
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
network_internals
labo_network
100 code=00a00100 msg="Ok\""""

        response = self.client.send_command('CONFIG WEBADMIN ACCESS SHOW')

        self.assertEqual(response.output, expected)
        self.assertEqual(response.ret, 100)

    def test_xml(self):
        """ xml text output """

        expected = """101 code=00a01000 msg="Begin" format="xml"
<data format="xml"><filters total_lines="5">
<separator collapse="0" color="c0c0c0" comment="Remote Management: Go to System - Configuration to setup the web administration application access" first_ruleid="1" nb_elements="2" position="1" />
<filter action="pass" comment="Admin from everywhere" index="1" position="2" status="active" type="local_filter_slot"><noconnlog disk="0" ipfix="0" syslog="0" /><from><target type="any" value="any" /></from><to><port type="single" value="firewall_srv" /><port type="single" value="https" /><target type="group" value="firewall_all" /></to></filter>
<filter action="pass" comment="Allow Ping from everywhere" icmp_code="0" icmp_type="8" index="2" ipproto="icmp" position="3" proto="none" status="active" type="local_filter_slot"><noconnlog disk="0" ipfix="0" syslog="0" /><from><target type="any" value="any" /></from><to><target type="group" value="firewall_all" /></to></filter>
<separator collapse="0" color="c0c0c0" comment="Default policy" first_ruleid="3" nb_elements="1" position="4" />
<filter action="block" comment="Block all" index="3" position="5" status="active" type="local_filter_slot"><noconnlog disk="0" ipfix="0" syslog="0" /><from><target type="any" value="any" /></from><to><target type="any" value="any" /></to></filter>
</filters>
</data>
100 code=00a00100 msg="Ok\""""

        response = self.client.send_command('CONFIG FILTER EXPLICIT index=1 type=filter output=xml')

        self.assertEqual(response.output, expected)
        self.assertEqual(response.ret, 100)

if __name__ == '__main__':
    unittest.main()

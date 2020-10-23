#!/usr/bin/python
# -*- coding: utf-8 -*-

import unittest
import json

from stormshield.sns.configparser import ConfigParser

class TestConfigParser(unittest.TestCase):

    def test_section(self):
        """ Get token from section """

        input = """101 code=00a01000 msg="Begin" format="section"
[Result]
Type="Firewall"
Model="V50-A"
MachineType="amd64"
Version="3.7.1"
ASQVersion="8.4.0"
100 code=00a00100 msg="Ok\""""

        expected = '3.7.1'

        config = ConfigParser(input)
        self.assertEqual(expected, config.get(section='Result', token='Version'))

    def test_default(self):
        """ Test default value """

        input = """101 code=00a01000 msg="Begin" format="section"
[Result]
Type="Firewall"
Model="V50-A"
MachineType="amd64"
Version="3.7.1"
ASQVersion="8.4.0"
100 code=00a00100 msg="Ok\""""

        expected = 1

        config = ConfigParser(input)
        self.assertEqual(expected, config.get(section='Result', token='DefaultConfig', default=1))

    def test_line(self):
        """ Get line from section """

        input = """101 code=00a01000 msg="Begin" format="list"
[Filter]
position=1; separator color="c0c0c0" comment="FQDN" collapse="0" nb_elements="1" first_ruleid="1"
position=2; usage=0 match=0 ruleid=1: pass log from group="ruser"@Network_lan domain storm to rr.labo.int # Created on 2016-05-20 13:25:24,by admin (10.2.9.2)
position=3; separator color="c0c0c0" comment="Office365" collapse="0" nb_elements="4" first_ruleid="2"
position=4; usage=0 match=0 ruleid=2: pass log tos 8 from Network_lan to outlook.office365.com # Créée le 2016-06-23 15:17:04, par admin (10.2.9.2)
position=5; usage=0 match=0 ruleid=3: pass settos 24 log from Network_lan to xsi.outlook.com # Créée le 2016-06-23 15:29:44, par admin (10.2.9.2)
position=6; usage=0 match=0 ruleid=4: pass log from Network_lan to webdir.online.lync.com # Créée le 2016-06-23 15:29:47, par admin (10.2.9.2)
position=7; separator color="c0c0c0" comment="DEFAULT" collapse="0" nb_elements="2" first_ruleid="14"
position=8; usage=3 match=24994 ruleid=14: pass from any to any
position=9; usage=0 match=0 ruleid=15: pass from any on out to Firewall_out port ssh # Allow SSH on OUT
100 code=00a00100 msg="Ok\"
"""

        expected = 'position=3; separator color="c0c0c0" comment="Office365" collapse="0" nb_elements="4" first_ruleid="2"'

        config = ConfigParser(input)
        self.assertEqual(expected, config.get(section='Filter', line=3))

    def test_get_sectionline(self):
        """ Get section_line section """

        input = """101 code=00a01000 msg="Begin" format="section_line"
[Result]
name=ntp1.stormshieldcs.eu keynum=none type=host
name="ntp2.stormshieldcs.eu" keynum=none type=host
100 code=00a00100 msg="Ok\""""

        expected = [
            {"name":"ntp1.stormshieldcs.eu", "keynum":"none", "type":"host"},
            {"name":"ntp2.stormshieldcs.eu", "keynum":"none", "type":"host"}
        ]

        config = ConfigParser(input)
        self.assertEqual(expected, config.get(section='Result'))


    def test_getall(self):
        """ Get all tokens of a section """

        input="""101 code=00a01000 msg="Begin" format="section"
[Server]
1=dnscache
2=dns1.google.com
100 code=00a00100 msg="Ok\""""

        expected = { "1":"dnscache", "2":"dns1.google.com"}

        config = ConfigParser(input)
        self.assertEqual(expected, config.get(section='Server'))

    def test_get_list(self):
        """ Get list section """

        input = """101 code=00a01000 msg="Begin" format="list"
[Result]
net1
net2
100 code=00a00100 msg="Ok\""""

        expected = ['net1', 'net2']

        config = ConfigParser(input)
        self.assertEqual(expected, config.get(section='Result'))

    def test_case_insensitive(self):
        """ Test key names are case insensitive """

        input = """101 code=00a01000 msg="Begin" format="section"
[Result]
token1=value1
token2=value2
100 code=00a00100 msg="Ok\""""

        config = ConfigParser(input)
        self.assertEqual('value1', config.get(section='result', token='TOKEN1'))
        self.assertEqual('value1', config.data['result']['TOKEN1'])

    def test_serialize(self):
        """ Test serialize data structure """

        input = """101 code=00a01000 msg="Begin" format="section"
[Server]
1="dns1"
2="dns2"
100 code=00a00100 msg="Ok\""""

        expected = {"Server": { "1": "dns1", "2": "dns2"}}

        config = ConfigParser(input)
        self.assertEqual(json.dumps(expected), json.dumps(config.serialize_data()))

        input = """101 code=00a01000 msg="Begin" format="section_line"
[Result]
name=ntp1.stormshieldcs.eu keynum=none type=host
name="ntp2.stormshieldcs.eu" keynum=none type=host
100 code=00a00100 msg="Ok\""""

        expected = {"Result": [
            {"name": "ntp1.stormshieldcs.eu", "keynum": "none", "type": "host"},
            {"name": "ntp2.stormshieldcs.eu", "keynum": "none", "type": "host"}
        ]}

        config = ConfigParser(input)
        self.assertEqual(json.dumps(expected), json.dumps(config.serialize_data()))

    def test_empty_value(self):
        """ Test empty value and value with ':' """

        input = """101 code=00a01000 msg="Begin" format="section_line"
[Object]
type=host global=0 name=Firewall_out ip=10.60.3.235 modify=0 comment=
type=host global=0 name=dnscache ip=10.2.0.1 modify=1 comment= resolve=dynamic
type=host global=0 name=myobject ip=1.2.3.4 modify=1 comment= mac=00:11:22:33:44:55
100 code=00a00100 msg="Ok\""""

        expected = {"Object": [
            {"type":"host", "global":"0", "name":"Firewall_out",
             "ip":"10.60.3.235", "modify":"0", "comment":""},
            {"type":"host", "global":"0", "name":"dnscache",
             "ip":"10.2.0.1", "modify":"1", "comment":"", "resolve":"dynamic"},
            {"type":"host", "global":"0", "name":"myobject",
             "ip":"1.2.3.4", "modify":"1", "comment":"", "mac":"00:11:22:33:44:55"}]}

        config = ConfigParser(input)
        self.assertEqual(expected, config.data)

    def test_slash_in_value(self):
        """ Test parsing of value with slash character """

        input = """101 code=00a01000 msg="Begin" format="section_line"
[StaticRoutes]
Remote=remote_net Address=172.21.0.0/24 Interface=out Gateway=remote_gw Protected=0 State=1 Comment=
100 code=00a00100 msg="Ok\""""

        expected = {'StaticRoutes': [
            {'Comment': '', 'Remote': 'remote_net', 'State': '1', 'Protected': '0',
             'Address': '172.21.0.0/24', 'Interface': 'out', 'Gateway': 'remote_gw'}]}

        config = ConfigParser(input)
        self.assertEqual(expected, config.data)

    def test_arobase_in_value(self):
        """ Test parsing of value with @ character """

        input = """101 code=00a01000 msg="Begin" format="section_line"
[Result]
ruleid=1 state=on action=pass from=*@* to=*@* comment="default rule (pass all)"
100 code=00a00100 msg="Ok"\""""

        expected = {'Result': [
            {'ruleid': '1', 'state': 'on', 'action': 'pass', 'from': '*@*',
             'to': '*@*', 'comment': 'default rule (pass all)'}]}

        config = ConfigParser(input)
        self.assertEqual(expected, config.data)


if __name__ == '__main__':
    unittest.main()

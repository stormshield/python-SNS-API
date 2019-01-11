#!/usr/bin/python

import random
import string
import os
import sys
import tempfile
import unittest
from stormshield.sns.sslclient import SSLClient

# APPLIANCE env var must be set to the ip/hostname of a running SNS appliance
if 'APPLIANCE' not in os.environ:
    APPLIANCE=""
else:
    APPLIANCE=os.environ['APPLIANCE']

@unittest.skipIf(APPLIANCE=="", "APPLIANCE env var must be set to the ip/hostname of a running SNS appliance")
class TestFormatIni(unittest.TestCase):
    """ Test file upload & download """

    def setUp(self):
        self.client = SSLClient(host=APPLIANCE, user='admin', password='adminadmin', sslverifyhost=False)

        self.tmpdir = tempfile.TemporaryDirectory()
        self.upload = os.path.join(self.tmpdir.name, 'upload')
        self.download = os.path.join(self.tmpdir.name, 'download')

    def tearDown(self):
        self.client.disconnect()
        self.tmpdir.cleanup()

    def test_upload_download(self):
        """ upload / download """

        #generate a random file
        content = "".join( [random.choice(string.ascii_letters) for i in range(15)] )
        with open(self.upload, "w") as fh:
            fh.write(content)

        response = self.client.send_command('CONFIG COMMUNICATION EMAIL TEMPLATE UPLOAD pvm_summary < ' + self.upload)
        self.assertEqual(response.ret, 100)
        self.client.send_command('CONFIG COMMUNICATION ACTIVATE')
        self.assertEqual(response.ret, 100)

        response = self.client.send_command('CONFIG COMMUNICATION EMAIL TEMPLATE DOWNLOAD pvm_summary > ' + self.download)
        self.assertEqual(response.ret, 100)

        with open(self.download, "r") as fh:
            downloaded = fh.read()

        self.assertEqual(content, downloaded)

if __name__ == '__main__':
    unittest.main()

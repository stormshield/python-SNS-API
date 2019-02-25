#!/usr/bin/python
# -*- coding: utf-8 -*-

from __future__ import unicode_literals
import random
import string
import os
import sys
import tempfile
import unittest
import shutil
from stormshield.sns.sslclient import SSLClient

APPLIANCE = os.getenv('APPLIANCE', "")
PASSWORD = os.getenv('PASSWORD', "")

@unittest.skipIf(APPLIANCE=="", "APPLIANCE env var must be set to the ip/hostname of a running SNS appliance")
@unittest.skipIf(PASSWORD=="", "PASSWORD env var must be set to the firewall password")
class TestFormatIni(unittest.TestCase):
    """ Test file upload & download """

    def setUp(self):
        self.client = SSLClient(host=APPLIANCE, user='admin', password=PASSWORD, sslverifyhost=False)

        self.tmpdir = tempfile.mkdtemp()
        self.upload = os.path.join(self.tmpdir, 'upload')
        self.download = os.path.join(self.tmpdir, 'download')

    def tearDown(self):
        self.client.disconnect()
        shutil.rmtree(self.tmpdir, ignore_errors=True)

    def test_upload_download(self):
        """ Test file upload and download """

        letters = string.ascii_letters + 'éèàÎîô'

        #generate a random file
        content = ("".join( [random.choice(letters) for i in range(2500)] )).encode('utf-8')
        with open(self.upload, "wb") as fh:
            fh.write(content)

        response = self.client.send_command('CONFIG COMMUNICATION EMAIL TEMPLATE UPLOAD pvm_summary < ' + self.upload)
        self.assertEqual(response.ret, 100)
        self.client.send_command('CONFIG COMMUNICATION ACTIVATE')
        self.assertEqual(response.ret, 100)

        response = self.client.send_command('CONFIG COMMUNICATION EMAIL TEMPLATE DOWNLOAD pvm_summary > ' + self.download)
        self.assertEqual(response.ret, 100)

        with open(self.download, "rb") as fh:
            downloaded = fh.read()

        self.assertEqual(content, downloaded)

if __name__ == '__main__':
    unittest.main()

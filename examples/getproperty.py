#!/usr/bin/python

"""
This example show how to connect to a SNS appliance, send a command
to get appliance properties and parse the result to extract the
appliance model and firmware version.
"""

import getpass

from stormshield.sns.sslclient import SSLClient

# user input
host = input("Appliance ip address: ")
user = input("User:")
password = getpass.getpass("Password: ")

# connect to the appliance
client = SSLClient(
    host=host, port=443,
    user=user, password=password,
    sslverifyhost=False)

# request appliance properties
response = client.send_command("SYSTEM PROPERTY")

if response:
    #get value using parser get method
    model = response.parser.get(section='Result', token='Model')
    # get value with direct access to data
    version = response.data['Result']['Version']

    print("")
    print("Model: {}".format(model))
    print("Firmware version: {}".format(version))
else:
    print("Command failed: {}".format(response.output))

client.disconnect()

#!/usr/bin/env python3

"""
Script to create a VLAN interface on a SNS appliance
"""

import sys
import getpass

from stormshield.sns.sslclient import SSLClient

# user input
host = input("Appliance ip address: ")
user = input("User:")
password = getpass.getpass("Password: ")
vlanname = input("VLAN name: ")
vlanphy = input("Physical interface: ")
vlantag = input("VLAN tag: ")
vlanaddr = input("Address: ")
vlanmask = input("Mask: ")

#host = "10.0.0.0.254"
#user = "admin"
#password = "mypassword"
#vlanname = "myvlan3"
#vlanphy = "Ethernet0"
#vlantag = 103
#vlanaddr = "192.168.103.1"
#vlanmask = "255.255.255.0"

MAXVLAN=60

# connect to the appliance
client = SSLClient(
    host=host, port=443,
    user=user, password=password,
    sslverifyhost=False)

def error(msg):
    global client

    print("ERROR: {}".format(msg))
    client.disconnect()
    sys.exit(1)

def command(cmd):
    global client

    response = client.send_command(cmd)
    if not response:
        error("command failed:\n{}".format(response.output))

    return response


# get vlan list & extract first available vlanX interface
response = command("config network interface show filter=vlan")
if len(response.data.keys()) == 0:
    vlanid = 0
else:
    vlanid = -1
    for i in range(MAXVLAN):
        if "vlan{}".format(i) not in response.data:
            vlanid = i
            break
    if vlanid == -1:
        error("all available VLAN already created")


response = command("CONFIG NETWORK INTERFACE CREATE state=1 protected=0 mtu=1500 physical={} name={} tag={} priority=0 keepVlanPriority=1 maxThroughput=0 ifname=vlan{} address={} mask={}".format(vlanphy, vlanname, vlantag, vlanid, vlanaddr, vlanmask))
if response.code:
    print("VLAN vlan{} created".format(vlanid))
else:
    error("VLAN vlan{} can't be created:\n{}".format(vlanid, response.output))

response = command("CONFIG NETWORK ACTIVATE")
if response.code:
    print("Configuration activated")
else:
    error("Can't activate network:\n{}".format(response.output))

client.disconnect()

# python-SNS-API

A Python client for the Stormshield Network Security appliance SSL API.

Note: this module requires python2.7 or python3.3

## API usage

```python
from stormshield.sns.sslclient import SSLClient

client = SSLClient(
    host="10.0.0.254", port=443,
    user='admin', password='password',
    sslverifyhost=False)

response = client.send_command("SYSTEM PROPERTY")

if response:
    model   = response.data['Result']['Model']
    version = response.data['Result']['Version']

    print("Model: {}".format(model))
    print("Firmware version: {}".format(version))
else:
    print("Command failed: {}".format(response.output))

client.disconnect()

```

### Command results

Command results are available in text, xml or python structure formats:

```python
>>> response = client.send_command("CONFIG NTP SERVER LIST")

>>> print(response.output)
101 code=00a01000 msg="Begin" format="section_line"
[Result]
name=ntp1.stormshieldcs.eu keynum=none type=host
name=ntp2.stormshieldcs.eu keynum=none type=host
100 code=00a00100 msg="Ok"

>>> print(response.xml)
<?xml version="1.0"?>
<nws code="100" msg="OK"><serverd ret="101" code="00a01000" msg="Begin"><data format="section_line"><section title="Result"><line><key name="name" value="ntp1.stormshieldcs.eu"/><key name="keynum" value="none"/><key name="type" value="host"/></line><line><key name="name" value="ntp2.stormshieldcs.eu"/><key name="keynum" value="none"/><key name="type" value="host"/></line></section></data></serverd><serverd ret="100" code="00a00100" msg="Ok"></serverd></nws>

>>> print(response.data)
{'Result': [{'name': 'ntp1.stormshieldcs.eu', 'keynum': 'none', 'type': 'host'}, {'name': 'ntp2.stormshieldcs.eu', 'keynum': 'none', 'type': 'host'}]}

```

The keys of the `data` property are case insensitive, `response.data['Result'][0]['name']` and `response.data['ReSuLt'][0]['NaMe']` will return the same value.

Results token are also available via `response.parser.get()` method which accepts a default parameter to return if the token is not present.

```python
>>> print(response.output)
101 code=00a01000 msg="Begin" format="section"
[Server]
1=dns1.google.com
2=dns2.google.com
100 code=00a00100 msg="Ok"

>>> print(response.data['Server']['3'])
Traceback (most recent call last):
  File "<stdin>", line 1, in <module>
  File "/usr/local/lib/python3.7/site-packages/requests/structures.py", line 52, in __getitem__
    return self._store[key.lower()][1]
KeyError: '3'

>>> print(response.parser.get(section='Server', token='3', default=None))
None

```

### File upload/download

Files can be downloaded or uploaded by adding a redirection to a file with '>' or '<' at the end of the configuration command.

```python
>>> client.send_command("CONFIG BACKUP list=all > /tmp/mybackup.na")
100 code=00a00100 msg="Ok"
```

## snscli

 `snscli` is a python cli for executing configuration commands and scripts on Stormshield Network Security appliances.

* Output format can be chosen between section/ini or xml
* File upload and download available with adding `< upload` or `> download` at the end of the command
* Client can execute script files using `--script` option.
* Comments are allowed with `#`

`$ snscli --host <utm>`

`$ snscli --host <utm> --user admin --password admin --script config.script`

Concerning the SSL validation:

* For the first connection to a new appliance, ssl host name verification can be bypassed with `--no-sslverifyhost` option.
* To connect to a known appliance with the default certificate use `--host <serial> --ip <ip address>` to validate the peer certificate.
* If a custom CA and certificate is installed, use `--host myfirewall.tld --cabundle <ca.pem>`.
* For client certificate authentication, the expected format is a PEM file with the certificate and the unencrypted key concatenated.

## Proxy

The library and `snscli` tool support HTTP and SOCKS proxies, use `--proxy scheme://user:password@host:port` option.


## Build

`$ python3 setup.py sdist bdist_wheel`


## Install

## From PyPI:

`$ pip3 install stormshield.sns.sslclient`

## From source:

`$ python3 setup.py install`


## Tests

Warning: some tests require a remote SNS appliance.

`$ PASSWORD=password APPLIANCE=10.0.0.254 python3 setup.py test`


To run `snscli` from the source folder without install:

`$ python3 stormshield/sns/cli.py --help`


## Links

* [Stormshield corporate website](https://www.stormshield.com)
* [CLI commands reference guide](https://documentation.stormshield.eu/SNS/v3/en/Content/CLI_Serverd_Commands_reference_Guide_v3/Introduction.htm)


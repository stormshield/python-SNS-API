#!/usr/bin/python
# -*- coding: utf-8 -*-

"""
stormshield.sns.sslclient
~~~~~~~~~~~~~~~~~~~~~~~~~

This module contains SSLClient class to handle SNS API calls
and Response class to handle API answers.
"""

from __future__ import unicode_literals
import os
import ipaddress
import base64
import logging
import re
import platform
import defusedxml.ElementTree as ElementTree
from xml.etree import ElementTree as Et
import requests
from requests.adapters import HTTPAdapter, DEFAULT_POOLSIZE, DEFAULT_RETRIES, DEFAULT_POOLBLOCK
from urllib3.poolmanager import PoolManager, proxy_from_url
from requests.utils import get_auth_from_url
from requests.exceptions import InvalidSchema
import requests.compat
from requests_toolbelt.multipart.encoder import MultipartEncoder
try:
    from urllib3.contrib.socks import SOCKSProxyManager
except ImportError:
    def SOCKSProxyManager(*args, **kwargs):
        raise InvalidSchema("Missing dependencies for SOCKS support.")

from stormshield.sns.configparser import ConfigParser
import stormshield.sns.crc as snscrc

from .__version__ import __version__

#disable ssl warnings, we have --sslverify* for that
requests.packages.urllib3.disable_warnings(
    requests.packages.urllib3.exceptions.InsecureRequestWarning)
requests.packages.urllib3.disable_warnings(
    requests.packages.urllib3.exceptions.SubjectAltNameWarning)
#disable http warning 'Received response with both Content-Length and Transfer-Encoding set'
logging.getLogger(requests.packages.urllib3.__name__).setLevel(logging.ERROR)

class HostNameIgnoringAdapter(HTTPAdapter):
    """ HTTP adapter to disable strict ssl host name verification """

    def init_poolmanager(self, connections, maxsize, block=False):
        self.poolmanager = PoolManager(num_pools=connections,
                                       maxsize=maxsize,
                                       block=block,
                                       assert_hostname=False)

    def proxy_manager_for(self, proxy, **proxy_kwargs):
        if proxy in self.proxy_manager:
            manager = self.proxy_manager[proxy]
        elif proxy.lower().startswith('socks'):
            username, password = get_auth_from_url(proxy)
            manager = self.proxy_manager[proxy] = SOCKSProxyManager(
                proxy,
                username=username,
                password=password,
                num_pools=self._pool_connections,
                maxsize=self._pool_maxsize,
                block=self._pool_block,
                assert_hostname=False,
                **proxy_kwargs
            )
        else:
            proxy_headers = self.proxy_headers(proxy)
            manager = self.proxy_manager[proxy] = proxy_from_url(
                proxy,
                proxy_headers=proxy_headers,
                num_pools=self._pool_connections,
                maxsize=self._pool_maxsize,
                block=self._pool_block,
                assert_hostname=False,
                **proxy_kwargs)

        return manager

class DNSResolverHTTPSAdapter(HTTPAdapter):
    """ HTTP adapter to check peer common_name with provided host name """

    def __init__(self, common_name, host, pool_connections=DEFAULT_POOLSIZE,
                 pool_maxsize=DEFAULT_POOLSIZE, max_retries=DEFAULT_RETRIES,
                 pool_block=DEFAULT_POOLBLOCK):
        self.__common_name = common_name
        self.__host = host
        super(DNSResolverHTTPSAdapter, self).__init__(pool_connections=pool_connections,
                                                      pool_maxsize=pool_maxsize,
                                                      max_retries=max_retries,
                                                      pool_block=pool_block)

    def init_poolmanager(self, connections, maxsize, block=DEFAULT_POOLBLOCK, **pool_kwargs):
        pool_kwargs['assert_hostname'] = self.__common_name
        super(DNSResolverHTTPSAdapter, self).init_poolmanager(connections,
                                                              maxsize,
                                                              block=block,
                                                              **pool_kwargs)

class Response():
    """ :class:`Response <Response>` object contains the SNS API response to a request """

    def __init__(self, code=None, ret=0, msg=None, output=None, xml=None):
        self.code = code
        self.ret = ret
        self.msg = msg
        self.output = output
        self.xml = xml

        self.parser = ConfigParser(output)
        self.data = self.parser.data
        self.format = self.parser.format

    def __repr__(self):
        return self.output

    def __bool__(self):
        """ Returns True if :attr:`ret` is OK or WARNING. """
        return self.ret >= 100 and self.ret < 200

def quote(value):
    """ Quote value if needed """
    try:
        if value and (type(value) == str or type(value) == unicode) and ' ' in value:
            return '"' + value + '"'
    except:
        # in python3 unicode class doesn't exists
        pass
    return value

def format_output(output):
    """ Format command output in ini/section or text format"""
    nws_node = ElementTree.fromstring(output)
    serverd_node = nws_node[0]
    ini = '{} code={} msg="{}"'.format(serverd_node.get('ret'),
                                       serverd_node.get('code'),
                                       serverd_node.get('msg'))
    if len(list(nws_node)) > 1:
        data_node = serverd_node[0]
        node_format = data_node.get('format')
        ini += ' format="{}"\n'.format(node_format)
        if node_format == 'raw':
            if data_node.text:
                ini += data_node.text
        elif node_format == 'section':
            for section_node in data_node:
                ini += '[{}]\n'.format(section_node.get('title'))
                for key_node in section_node:
                    ini += '{}={}\n'.format(key_node.get('name'),
                                            quote(key_node.get('value')))
        elif node_format == 'section_line':
            for section_node in data_node:
                ini += '[{}]\n'.format(section_node.get('title'))
                for line_node in section_node:
                    tokens = []
                    for key_node in line_node:
                        tokens.append('{}={}'.format(key_node.get('name'),
                                                     quote(key_node.get('value'))))
                    ini += " ".join(tokens) + "\n"
        elif node_format == 'list':
            for section_node in data_node:
                ini += '[{}]\n'.format(section_node.get('title'))
                for line_node in section_node:
                    ini += "{}\n".format(line_node.text)
        elif node_format == 'xml':
            # display xml data node
            ini += Et.tostring(data_node).decode() + "\n"
        serverd_node = nws_node[1]
        ini += '{} code={} msg="{}"'.format(serverd_node.get('ret'),
                                            serverd_node.get('code'),
                                            serverd_node.get('msg'))
    return ini

class MissingHost(ValueError):
    """ The remote host is missing """

class MissingAuth(ValueError):
    """ password or user certificate is missing """

class MissingCABundle(ValueError):
    """ The certificate authority bundle is missing """

class AuthenticationError(Exception):
    """ authentication failed """

class ServerError(Exception):
    """ NWS server error """

class FileError(Exception):
    """ file access error """

class SSLClient:
    """SSL client to SNS configuration API """

    SSL_SERVERD_OK = 100
    SSL_SERVERD_REQUEST_ERROR = 200
    SSL_SERVERD_UNKNOWN_COMMAND = 201
    SSL_SERVERD_ERROR_COMMAND = 202
    SSL_SERVERD_INVALID_SESSION = 203
    SSL_SERVERD_EXPIRED_SESSION = 204
    SSL_SERVERD_AUTH_ERROR = 205
    SSL_SERVERD_PENDING_TRANSFER = 206
    SSL_SERVERD_PENDING_UPLOAD = 207
    SSL_SERVERD_OVERHEAT = 500
    SSL_SERVERD_UNREACHABLE = 501
    SSL_SERVERD_DISCONNECTED = 502
    SSL_SERVERD_INTERNAL_ERROR = 900

    SSL_SERVERD_MSG = {
        SSL_SERVERD_REQUEST_ERROR: "Request error",
        SSL_SERVERD_UNKNOWN_COMMAND: "Unknown command",
        SSL_SERVERD_ERROR_COMMAND: "Command error",
        SSL_SERVERD_INVALID_SESSION: "Invalid session",
        SSL_SERVERD_EXPIRED_SESSION: "Expired session",
        SSL_SERVERD_AUTH_ERROR: "Authentication error",
        SSL_SERVERD_PENDING_TRANSFER: "Pending transfer",
        SSL_SERVERD_PENDING_UPLOAD: "Upload pending",
        SSL_SERVERD_OVERHEAT: "Server overheat",
        SSL_SERVERD_UNREACHABLE: "Server unreachable",
        SSL_SERVERD_DISCONNECTED: "Server disconnected",
        SSL_SERVERD_INTERNAL_ERROR: "Internal error"
    }

    SRV_RET_OK = 100
    SRV_RET_DOWNLOAD = 101
    SRV_RET_UPLOAD = 102
    SRV_RET_LASTCMD = 103
    SRV_RET_MUSTREBOOT = 104
    SRV_RET_WARNING = 110
    SRV_RET_MULTIWARN = 111
    SRV_RET_COMMAND = 200
    SRV_RET_MULTILINE = 201
    SRV_RET_AUTHFAILED = 202
    SRV_RET_IDLE = 203
    SRV_RET_AUTHLIMIT = 204
    SRV_RET_AUTHLEVEL = 205
    SRV_RET_LICENCE = 206

    SRV_RET_MSG = {
        SRV_RET_OK: 'Command successful',
        SRV_RET_DOWNLOAD: 'Command successful, download follow',
        SRV_RET_UPLOAD: 'Command successful, upload follow',
        SRV_RET_LASTCMD: 'Command successful, you will be disconnected',
        SRV_RET_MUSTREBOOT: 'Command successful, but reboot needed',
        SRV_RET_WARNING: 'Command successful, but warning',
        SRV_RET_MULTIWARN: 'Command successful, but multiple warnings',
        SRV_RET_COMMAND: 'Command error',
        SRV_RET_MULTILINE: 'Return error message on many lines',
        SRV_RET_AUTHFAILED: 'Authentication failed',
        SRV_RET_IDLE: 'Client is idle, disconnecting',
        SRV_RET_AUTHLIMIT: 'Maximum number of authentication user reached for that level',
        SRV_RET_AUTHLEVEL: 'Not enough privilege',
        SRV_RET_LICENCE: 'Licence restriction'
    }

    SERVERD_WAIT_DOWNLOAD = "00a01c00"
    SERVERD_WAIT_UPLOAD = "00a00300"
    AUTH_SUCCESS = "AUTH_SUCCESS"
    AUTH_FAILED = "AUTH_FAILED"

    fileregexp = re.compile(r'(.*)\s*(\<|\>)\s*(.*)\s*')

    CHUNK_SIZE = 10240 # bytes

    def __init__(self, user='admin', password=None, host=None, ip=None, port=443, cabundle=None,
                 sslverifypeer=True, sslverifyhost=True, credentials=None,
                 usercert=None, autoconnect=True, proxy=None, timeout=None):
        """:class:`SSLclient <SSLClient>` constructor.

        :param user: Optional user name.
        :param password: Optional password.
        :param host: hostname to connect or certificate common name (appliance serial).
        :param ip: Optional ip address to connect.
        :param port: Optional port number.
        :param cabundle: Optional certificat authorities bundle file in PEM format.
        :param sslverifypeer: Optional boolean to verify remote certificate authority.
        :param sslverifyhost: Optional boolean to verify remote certificate common name.
        :param credentials: Optional list of requested privileges.
        :param usercert: Optional user certificate.
        :param autoconnect: Connect to the appliance at initialization
        :param proxy: https proxy url (socks5://user:pass@host:port  http://user:password@host/)
        :param timeout: connection and read timeout in seconds
        """

        self.user = user
        self.password = password
        self.host = host
        self.ip = ip
        self.port = port
        self.cabundle = cabundle
        self.app = 'sslclient'
        self.sslverifypeer = sslverifypeer
        self.sslverifyhost = sslverifyhost
        self.credentials = credentials
        self.usercert = usercert
        self.sessionid = ""
        self.protocol = ""
        self.sessionlevel = ""
        self.dl_size = 0
        self.dl_crc = ""
        self.autoconnect = autoconnect
        self.proxy = proxy
        self.conn_options = {}

        if host is None:
            raise MissingHost("Host parameter must be provided")
        if password is None and usercert is None:
            raise MissingAuth("Password parameter must be provided")
        if usercert is not None and not os.path.isfile(usercert):
            raise MissingAuth("User certificate not found")
        if cabundle is None:
            # use default cabundle
            self.cabundle = os.path.normpath(os.path.join(os.path.dirname(__file__), "..", 'bundle.ca'))
        if not os.path.isfile(self.cabundle):
            raise MissingCABundle("Certificate authority bunble not found")

        #test ipv6 address
        try:
            ipaddress.IPv6Address(self.host)
            urlhost = "[{}]".format(self.host)
        except ipaddress.AddressValueError:
            urlhost = self.host

        self.baseurl = 'https://' + urlhost + ':' + str(self.port)

        self.headers = {
            'user-agent': 'stormshield.sns.sslclient/{} ({})'.format(
                __version__, platform.platform())
        }

        self.session = requests.Session()
        if self.sslverifypeer:
            self.session.verify = self.cabundle
        else:
            self.session.verify = False

        if not self.sslverifyhost:
            self.session.mount(self.baseurl, HostNameIgnoringAdapter())

        if self.ip is not None:
            #test ipv6 address
            try:
                ipaddress.IPv6Address(self.ip)
                urlip = "[{}]".format(self.ip)
            except ipaddress.AddressValueError:
                urlip = self.ip
            self.baseurl = 'https://' + urlip + ':' + str(self.port)
            self.session.mount(self.baseurl.lower(), DNSResolverHTTPSAdapter(self.host, self.ip))

        if self.usercert is not None:
            self.session.cert = self.usercert

        if self.proxy:
            self.session.proxies = { "https": self.proxy}

        if timeout is not None:
            self.conn_options = { "timeout": timeout }

        self.logger = logging.getLogger()

        if self.autoconnect:
            self.connect()

    @staticmethod
    def get_completer():
        """ Get the path to the installed cmd.complete file """
        return os.path.normpath(os.path.join(os.path.dirname(__file__), "..", 'cmd.complete'))

    def connect(self):
        """ Connect to the server """

        self.logger.log(logging.INFO, 'Connecting to %s on port %d with user %s%s',
                        self.host, self.port, self.user, " (proxy {})".format(self.proxy) if self.proxy else "")

        # 1. Authentication and get cookie
        if self.usercert is not None:
            # user cert authentication
            request = self.session.get(
                self.baseurl + '/auth/admin.html?sslcert=1&app={}'.format(self.app),
                headers=self.headers, **self.conn_options)
        else:
            # password authentication
            request = self.session.post(
                self.baseurl + '/auth/admin.html',
                data={
                    'uid':base64.b64encode(self.user.encode('utf-8')),
                    'pswd':base64.b64encode(self.password.encode('utf-8')),
                    'app':self.app},
                headers=self.headers,
                **self.conn_options)

        self.logger.log(logging.DEBUG, request.text)

        try:
            nws_node = ElementTree.fromstring(request.content)
            msg = nws_node.attrib['msg']
        except:
            raise AuthenticationError("Can't decode authentication result")

        if  msg != self.AUTH_SUCCESS:
            raise AuthenticationError("Authentication failed")

        # 2. Serverd session
        data = {'app': self.app, 'id': 0}
        if self.credentials is not None:
            data['reqlevel'] = self.credentials
        request = self.session.post(
            self.baseurl + '/api/auth/login',
            data=data,
            headers=self.headers,
            **self.conn_options)

        self.logger.log(logging.DEBUG, request.text)

        if request.status_code == requests.codes.OK:
            nws_node = ElementTree.fromstring(request.content)
            ret = int(nws_node.attrib['code'])
            msg = nws_node.attrib['msg']

            if ret != self.SSL_SERVERD_OK:
                raise ServerError("ERROR: {} {}".format(ret, msg))

            self.sessionid = nws_node.find('sessionid').text
            self.protocol = nws_node.find('protocol').text
            self.sessionlevel = nws_node.find('sessionlevel').text

            self.logger.log(logging.DEBUG, "Session ID: %s", self.sessionid)
            self.logger.log(logging.DEBUG, "Protocol: %s", self.protocol)
            self.logger.log(logging.DEBUG, "Session level: %s", self.sessionlevel)

        else:
            raise ServerError("can't get serverd session")



    def disconnect(self):
        """ Disconnect from the server """

        request = self.session.get(
            self.baseurl + '/api/auth/logout?sessionid=' + self.sessionid,
            headers=self.headers, **self.conn_options)

        if request.status_code == requests.codes.OK:
            self.logger.log(logging.INFO, 'Disconnected from %s', self.host)
        else:
            self.logger.log(logging.ERROR, 'Disconnect failed')

        self.session.close()

    def nws_parse(self, code):
        """ Parse server response """

        if code == self.SSL_SERVERD_OK:
            return

        if code in self.SSL_SERVERD_MSG:
            raise ServerError(self.SSL_SERVERD_MSG[code])
        else:
            raise ServerError("Unknown error")

    def send_command(self, command):
        """Execute a NSRPC command on the remote appliance.

        :param command: SNS API command. Files can be uploaded by adding '< filename'
            at the end of the command. Downloads are handled with '> filename'.
        :return: :class:`Response <Response>` object
        :rtype: stormshield.sns.Response
        """

        filename = None
        result = self.fileregexp.match(command)
        if result:
            command = result.group(1)
            filename = result.group(3)

        request = self.session.get(
            self.baseurl + '/api/command?sessionid=' + self.sessionid +
            '&cmd=' + requests.compat.quote(command.encode('utf-8')), # manually done since we need %20 encoding
            headers=self.headers,  **self.conn_options)

        self.logger.log(logging.DEBUG, request.text)

        if request.status_code == requests.codes.OK:
            nws_node = ElementTree.fromstring(request.content)
            code = int(nws_node.attrib['code'])
            self.nws_parse(code)
            serverd = nws_node[0]

            if serverd is not None:
                serverd_code = serverd.attrib['code']
                serverd_ret = int(serverd.attrib['ret'])
                serverd_msg = serverd.attrib['msg']

                response = Response(ret=serverd_ret,
                                    code=serverd_code,
                                    msg=serverd_msg,
                                    output=format_output(request.content),
                                    xml=request.text)

                #multiline answer get the final code
                if len(list(nws_node)) > 1:
                    response.code = nws_node[1].get('code')
                    response.msg = nws_node[1].get('msg')
                    response.ret = int(nws_node[1].get('ret'))

                if serverd_code == self.SERVERD_WAIT_UPLOAD:
                    if filename:
                        return self.upload(filename)
                    return response

                if serverd_code == self.SERVERD_WAIT_DOWNLOAD:
                    data = serverd.find('data')
                    # keep size and crc for further verification
                    if data.get('format') == 'section':
                        # <data format="section"><section title="Result"><key name="format" value="base64,crc=923B2C86,size=952"/>
                        key = data.find('section').find('key')
                        values = key.get('value').split(',')
                        self.dl_size = int(values[2].split('=')[1])
                        self.dl_crc = values[1].split('=')[1]
                    else:
                        # <data format="raw"><crc>439B852</crc><size>5096
                        self.dl_size = int(data.find('size').text)
                        self.dl_crc = data.find('crc').text
                    if filename:
                        return self.download(filename)
                    return response
        else:
            raise ServerError("HTTP error {}".format(request.status_code))

        return response

    def download(self, filename):
        """ handle file download """

        request = self.session.get(
            self.baseurl + '/api/download/tmp.file?sessionid=' + self.sessionid,
            headers=self.headers,
            stream=True,
            **self.conn_options)

        if request.status_code == requests.codes.OK:
            size = 0
            crc = snscrc.CRC32_init
            try:
                with open(filename, "wb") as savefile:
                    for chunk in request.iter_content(self.CHUNK_SIZE):
                        savefile.write(chunk)
                        size += len(chunk)
                        crc = snscrc.update_crc32(chunk, crc)
            except Exception as exception:
                self.logger.log(logging.ERROR, str(exception))
                raise FileError("Can't save file")

            if size != self.dl_size:
                raise ServerError("Download error: {} bytes downloaded, expecting {} bytes".format(
                    size, self.dl_size))

            crc = "%X" % (crc)

            if crc != self.dl_crc:
                raise ServerError("Download error: crc {}, expecting {}".format(crc, self.dl_crc))

            return Response(ret=100, code='00a00100', msg='OK',
                            output='100 code=00a00100 msg="Ok"',
                            xml='<?xml version="1.0" ?><nws code="100" msg="OK">' +
                            '<serverd code="00a00100" msg="Ok" ret="100"/>')

        raise ServerError("HTTP error {}".format(request.status_code))

    def upload(self, filename):
        """ handle file upload """

        uploadh = open(filename, 'rb')

        data = MultipartEncoder(
            fields={'upload': uploadh}
        )
        headers = self.headers
        headers['Content-Type'] = data.content_type

        request = self.session.post(
            self.baseurl + '/api/upload?sessionid=' + self.sessionid,
            headers=headers,
            data=data,
            **self.conn_options)

        uploadh.close()

        if request.status_code == requests.codes.OK:
            nws_node = ElementTree.fromstring(request.content)
            code = int(nws_node.attrib['code'])
            self.nws_parse(code)

            return Response(code=nws_node[0].get('code'),
                            ret=int(nws_node[0].get('ret')),
                            msg=nws_node[0].get('msg'),
                            output=format_output(request.content),
                            xml=request.text)

        raise ServerError("HTTP error {}".format(request.status_code))

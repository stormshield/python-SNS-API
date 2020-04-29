#!/usr/bin/env python

""" cli to connect to Stormshield Network Security appliances"""

from __future__ import unicode_literals
import sys
import os
import re
import logging
import logging.handlers
import readline
import getpass
import atexit
import defusedxml.minidom
import argparse
import platform
from pygments import highlight
from pygments.lexers import XmlLexer
from pygments.formatters import TerminalFormatter
from colorlog import LevelFormatter

from stormshield.sns.sslclient import SSLClient, ServerError
from stormshield.sns.sslclient.__version__ import __version__ as libversion

# define missing exception for python2
try:
    FileNotFoundError
except NameError:
    FileNotFoundError = IOError

OUTPUT_LEVELV_NUM = 60 # log command response
COMMAND_LEVELV_NUM = 59 # log command input
FORMATTER = LevelFormatter(
    fmt={
        'DEBUG':    "%(log_color)s%(levelname)-8s%(reset)s %(message)s",
        'INFO':     "%(log_color)s%(levelname)-8s%(reset)s %(message)s",
        'WARNING':  "%(log_color)s%(levelname)-8s%(reset)s %(message)s",
        'ERROR':    "%(log_color)s%(levelname)-8s%(reset)s %(message)s",
        'CRITICAL': "%(log_color)s%(levelname)-8s%(reset)s %(message)s",
        'OUTPUT':   "%(message)s",
        'COMMAND':  "%(message)s"
    },
    datefmt=None,
    reset=True,
    log_colors={
        'DEBUG': 'green',
        'INFO': 'cyan',
        'WARNING': 'yellow',
        'ERROR': 'red',
        'CRITICAL': 'red,bg_white'
    },
    secondary_log_colors={},
    style='%'
)

class CommandFilter(logging.Filter):
    def filter(self, record):
        if record.levelname == 'COMMAND':
            return False
        return True

EMPTY_RE = re.compile(r'^\s*$')

def make_completer():
    """ load completer for readline """
    vocabulary = []
    with open(SSLClient.get_completer(), "r") as completelist:
        for line in completelist:
            vocabulary.append(line.replace('.', ' ').strip('\n'))

    def custom_complete(text, state):
        results = [x for x in vocabulary if x.startswith(text)] + [None]
        return results[state]
    return custom_complete

def main():

    # parse command line

    parser = argparse.ArgumentParser(conflict_handler="resolve")

    group = parser.add_argument_group("Connection parameters")
    group.add_argument("-h", "--host",  help="Remote UTM",    default=None)
    group.add_argument("-i", "--ip",    help="Remote UTM ip", default=None)
    group.add_argument("-P", "--port",  help="Remote port",   default=443, type=int)
    group.add_argument("--proxy",       help="Proxy URL (scheme://user:password@host:port)", default=None)
    group.add_argument("-t", "--timeout",  help="Connection timeout in seconds", default=-1, type=int)

    group = parser.add_argument_group("Authentication parameters")
    group.add_argument("-u", "--user",     help="User name",             default="admin")
    group.add_argument("-p", "--password", help="Password",              default=None)
    group.add_argument("-U", "--usercert", help="User certificate file", default=None)

    group = parser.add_argument_group("SSL parameters")
    group.add_argument("-C", "--cabundle",         help="CA bundle file",                     default=None)
    group.add_argument("--sslverifypeer",          help="Strict SSL CA check",                default=True, action="store_true")
    group.add_argument("-k", "--no-sslverifypeer", help="Disable strict SSL CA check",        default=True, action="store_false", dest="sslverifypeer")
    group.add_argument("--sslverifyhost",          help="Strict SSL host name check",         default=True, action="store_true")
    group.add_argument("-K", "--no-sslverifyhost", help="Disable strict SSL host name check", default=True, action="store_false", dest="sslverifyhost")

    group = parser.add_argument_group("Protocol parameters")
    group.add_argument("-c", "--credentials",  help="Privilege list",          default=None)
    group.add_argument("-s", "--script",       help="Command script",          default=None)
    group.add_argument("-o", "--outputformat", help="Output format (ini|xml)", default="ini")

    parser.add_argument("--version", help="Library version", default=False, action="store_true")

    group = parser.add_argument_group("Logging parameters")
    exclusive  = group.add_mutually_exclusive_group()
    exclusive.add_argument("-v", "--verbose", help="Increase logging output", default=False, action="store_true")
    exclusive.add_argument("-q", "--quiet",   help="Decrease logging output", default=False, action="store_true")
    group.add_argument("--loglvl",  help="Set explicit log level",      default=None,  choices=['DEBUG', 'INFO', 'WARNING', 'ERROR', 'CRITICAL'])
    group.add_argument("--logfile", help='Output log messages to file', default=None)

    args = parser.parse_args()

    host = args.host
    ip = args.ip
    usercert = args.usercert
    cabundle = args.cabundle
    password = args.password
    port = args.port
    proxy = args.proxy
    timeout = args.timeout
    user = args.user
    sslverifypeer = args.sslverifypeer
    sslverifyhost = args.sslverifyhost
    credentials = args.credentials
    script = args.script
    outputformat = args.outputformat
    version = args.version

    # logging

    level = logging.INFO
    if args.loglvl is not None:
        level = logging.getLevelName(args.loglvl)
    elif args.verbose:
        level = logging.DEBUG
    elif args.quiet:
        level = logging.WARNING

    # add custom level
    logging.addLevelName(OUTPUT_LEVELV_NUM, "OUTPUT")
    logging.addLevelName(COMMAND_LEVELV_NUM, "COMMAND")

    def logoutput(self, message, *args, **kwargs):
        # Yes, logger takes its '*args' as 'args'.
        self._log(OUTPUT_LEVELV_NUM, message, args, **kwargs)
    def logcommand(self, message, *args, **kwargs):
        # Yes, logger takes its '*args' as 'args'.
        self._log(COMMAND_LEVELV_NUM, message, args, **kwargs)

    logging.Logger.output = logoutput
    logging.Logger.command = logcommand

    # logger
    logger = logging.getLogger()
    for handler in logger.handlers:
        logger.removeHandler(handler)
    logger.setLevel(level)

    # attach handlers
    handler = logging.StreamHandler(sys.stdout)
    handler.addFilter(CommandFilter())
    logger.addHandler(handler)
    if args.logfile is not None:
        if platform.system() != 'Windows':
            handler = logging.handlers.WatchedFileHandler(args.logfile)
        else:
            handler = logging.FileHandler(args.logfile)
        logger.addHandler(handler)

    for handler in logger.handlers:
        if handler.__class__ == logging.StreamHandler:
            handler.setFormatter(FORMATTER)

    if version:
        logging.info("snscli - stormshield.sns.sslclient version {}".format(libversion))
        sys.exit(0)

    if script is not None:
        try:
            script = open(script, 'r')
        except Exception as exception:
            logging.error("Can't open script file - %s", str(exception))
            sys.exit(1)

    if outputformat not in ['ini', 'xml']:
        logging.error("Unknown output format")
        sys.exit(1)

    if host is None:
        logging.error("No host provided")
        sys.exit(1)

    if password is None and usercert is None:
        password = getpass.getpass()

    if timeout == -1:
        timeout = None

    try:
        client = SSLClient(
            host=host, ip=ip, port=port, user=user, password=password,
            sslverifypeer=sslverifypeer, sslverifyhost=sslverifyhost,
            credentials=credentials, proxy=proxy, timeout=timeout,
            usercert=usercert, cabundle=cabundle, autoconnect=False)
    except Exception as exception:
        logging.error(str(exception))
        sys.exit(1)

    try:
        client.connect()
    except Exception as exception:
        search = re.search(r'doesn\'t match \'(.*)\'', str(exception))
        if search:
            logging.error(("Appliance name can't be verified, to force connection "
                           "use \"--host %s --ip %s\" or \"--no-sslverifyhost\" "
                           "options"), search.group(1), host)
        else:
            logging.error(str(exception))
        sys.exit(1)

    # disconnect gracefuly at exit
    atexit.register(client.disconnect)

    if script is not None:
        for cmd in script.readlines():
            cmd = cmd.strip('\r\n')
            logger.output(cmd)
            if cmd.startswith('#'):
                continue
            if EMPTY_RE.match(cmd):
                continue
            try:
                response = client.send_command(cmd)
            except Exception as exception:
                logging.error(str(exception))
                sys.exit(1)
            if outputformat == 'xml':
                logger.output(highlight(defusedxml.minidom.parseString(response.xml).toprettyxml(),
                                XmlLexer(), TerminalFormatter()))
            else:
                logger.output(response.output)
        sys.exit(0)

    # Start cli

    # load history
    histfile = os.path.join(os.path.expanduser("~"), ".sslclient_history")
    try:
        readline.read_history_file(histfile)
        readline.set_history_length(1000)
    except FileNotFoundError:
        pass

    def save_history(histfile):
        try:
            readline.write_history_file(histfile)
        except:
            logging.warning("Can't write history")

    atexit.register(save_history, histfile)

    # load auto-complete
    readline.parse_and_bind('tab: complete')
    readline.set_completer_delims('')
    readline.set_completer(make_completer())

    while True:
        try:
            cmd = input("> ")
            logger.command(cmd)
        except EOFError:
            break

        # skip comments
        if cmd.startswith('#'):
            continue

        try:
            response = client.send_command(cmd)
        except ServerError as exception:
            # do not log error on QUIT
            if "quit".startswith(cmd.lower()) \
               and str(exception) == "Server disconnected":
                sys.exit(0)
            logging.error(str(exception))
            sys.exit(1)
        except Exception as exception:
            logging.error(str(exception))
            sys.exit(1)

        if response.ret == client.SRV_RET_DOWNLOAD:
            filename = input("File to save: ")
            try:
                client.download(filename)
                logging.info("File downloaded")
            except Exception as exception:
                logging.error(str(exception))
        elif response.ret == client.SRV_RET_UPLOAD:
            filename = input("File to upload: ")
            try:
                client.upload(filename)
                logging.info("File uploaded")
            except Exception as exception:
                logging.error(str(exception))
        else:
            if outputformat == 'xml':
                logger.output(highlight(defusedxml.minidom.parseString(response.xml).toprettyxml(),
                                XmlLexer(), TerminalFormatter()))
            else:
                logger.output(response.output)

# use correct input function with python2
try:
    input = raw_input
except NameError:
    pass

if __name__ == "__main__":
    # execute only if run as a script
    main()

#!/usr/bin/python

"""
stormshield.sns.configparser

This module handles SNS API responses and extract section/token/values
in ini/section format.
"""

import sys
import re
from shlex import shlex
from requests.structures import CaseInsensitiveDict

def unquote(value):
    """ remove quotes if needed """
    if isinstance(value, str) and len(value) > 1 and value[0] == '"' and value[-1] == '"':
        return value[1:-1]
    return value

def serialize(data):
    if type(data) is CaseInsensitiveDict:
        res = {}
        for (k, v) in data.items():
            res[k] = serialize(v)
        return res
    elif type(data) is list:
        res = []
        for v in data:
            res.append(serialize(v))
        return res
    else:
        return data


class ConfigParser:
    """ A class to parse section format from SNS API responses """

    SERVERD_HEAD_RE = re.compile(r'^\d{3} code=.* msg=.* format="(.*?)"')
    SERVERD_TAIL_RE = re.compile(r'^\d{3} code=.*? msg=.*?')
    SECTION_RE = re.compile(r'^\s*\[\s*(.+?)\s*\]\s*$')
    EMPTY_RE = re.compile(r'^\s*$')
    TOKEN_VALUE_RE = re.compile(r'^(.*?)=(.*)$')

    def __init__(self, text):
        """ load a section from text """

        self.data = CaseInsensitiveDict()
        self.format = None

        lines = text.splitlines()

        # strip serverd headers if needed
        match = self.SERVERD_HEAD_RE.match(lines[0])
        if match:
            del lines[0]
            self.format = match.group(1)
        if self.SERVERD_TAIL_RE.match(lines[-1]):
            del lines[-1]

        text = "\n".join(lines)

        if self.format == 'raw' or self.format == 'xml':
            # plain data, no parsing
            self.data = text
            return

        section = "Result" # default section
        for line in text.splitlines():

            # comment
            if line.startswith('#'):
                continue

            # empty lines
            if self.EMPTY_RE.match(line):
                continue

            # section header
            match = self.SECTION_RE.match(line)
            if match:
                section = match.group(1)
                if self.format == 'section':
                    self.data[section] = CaseInsensitiveDict()
                else:
                    self.data[section] = []
                continue

            if self.format == "list":
                self.data[section].append(line)
            elif self.format == "section_line":
                # fix encoding for python2
                if sys.version_info[0] < 3:
                    line = line.encode('utf-8')
                # parse token=value token2=value2
                lexer = shlex(line, posix=True)
                lexer.wordchars += "=.-*:,/@"
                parsed = {}
                for word in lexer:
                    # ignore anything else than token=value
                    if '=' in word:
                        token, value = word.split("=", 1)
                        parsed[token] = value
                self.data[section].append(parsed)
            else:
                # section
                (token, value) = line.split("=", 1)
                self.data[section][token] = unquote(value)


    def get(self, section, token=None, line=None, default=None):
        """ get the value of a token or a plain line from the current section """

        if section not in self.data:
            value = default

        elif token is not None:
            # token/value mode

            if token not in self.data[section]:
                value = default
            else:
                value = unquote(self.data[section][token])
        elif line is None:
            # return all tokens/lines form section
            if self.format == "section":
                value = self.data[section]
            elif section not in self.data:
                value = []
            else:
                value = self.data[section]
        else:
            if line < 1:
                value = default
            elif section not in self.data:
                value = default
            elif len(self.data[section]) < line:
                value = default
            else:
                value = self.data[section][line-1]

        return value

    def serialize_data(self):
        """ return serializable output parsed data """

        return serialize(self.data)

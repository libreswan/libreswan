#!/usr/bin/env python3

# Script to install base domain
#
# Copyright (C) 2021-2023  Andrew Cagney
#
# This program is free software; you can redistribute it and/or modify it
# under the terms of the GNU General Public License as published by the
# Free Software Foundation; either version 2 of the License, or (at your
# option) any later version.  See <https://www.gnu.org/licenses/gpl2.txt>.
#
# This program is distributed in the hope that it will be useful, but
# WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY
# or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License
# for more details.

# Possibly useful reference:
# http://meta.libera.cc/2020/12/quick-netbsd-serial-console-install-on.html

import sys
import os
import sys
import pexpect
import re

import alpine
import debian
import fedora
import freebsd
import netbsd
import openbsd

args = sys.argv[1:]

# save param value pairs

class param:
    None

while args[0] != "--":
    key = args[0]
    value = args[1]
    print(key, value)
    setattr(param, key, value)
    args = args[2:]

# drop --
command = args[1:]
print("command", command)

#argv[0] is this script
OS = {
    "alpine": alpine,
    "debian": debian,
    "fedora": fedora,
    "freebsd": freebsd,
    "linux": fedora,
    "netbsd": netbsd,
    "openbsd": openbsd
}

for os in OS:
    for attr in ["install_base", "FILTER_OUTPUT"]:
        # will barf when missing
        getattr(OS[os], attr)

os = OS[param.os]

# Strip output of any escape sequences.  This does the stripping on
# the input side but seems to cause pexpect to hang.  See
# https://web.archive.org/web/20200805075926/http://ascii-table.com/ansi-escape-sequences.php

class AsciiDecoder(object):
    def __init__(self):
        self.buf = b''
    def encode(self, b, final=False):
        return b
    def decode(self, b, final=False):
        self.buf = self.buf + b
        i = self.buf.find(b'\n')
        if i >= 0:
            c = self.buf[0:i+1]
            self.buf = self.buf[i+1:]
            d = re.sub(rb'\x1b\[[0-9;=?]*[HfABCDsuJKmhlr]', b'*', c)
            e = re.sub(rb'\x1b', b'<ESC>', d)
            if e != e:
                print(">", e, "<")
            return e
        return b''

# This strips things on the output side, problem is that it often
# doesn't see the full escape sequence so would get things wrong.

class Filter:
    def __init__(self):
        self.stream=sys.stdout.buffer
    def write(self, record):
        #print(record)
        c = record
        d = re.sub(rb'\x1b\[[0-9;=?]*[HfABCDsuJKmhlr]', b'', c)
        # exclude all but 0x0a, 0x0d, ' '-DEL-1
        e = re.sub(rb'[\x00-\x09\x0b-\x0c\x0e-\x1f\x7f-\xff]', b'', d)
        self.stream.write(e);
    def flush(self):
        self.stream.flush()

class Raw:
    def __init__(self):
        self.stream=sys.stdout.buffer
    def write(self, record):
        self.stream.write(record);
    def flush(self):
        self.stream.flush()

if os.FILTER_OUTPUT:
    logfile = Filter()
else:
    logfile = Raw()

child = pexpect.spawn(command=command[0],
                      args=command[1:],
                      logfile=logfile,
                      echo=False)

os.install_base(child, param)

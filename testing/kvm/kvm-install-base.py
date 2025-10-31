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
import linux
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
    "linux": linux,
    "netbsd": netbsd,
    "openbsd": openbsd
}

for os in OS:
    for attr in ["install_base", "FILTER_OUTPUT"]:
        # will barf when missing
        getattr(OS[os], attr)

os = OS[param.os]

# Strip output of any escape sequences on the input side of pexpect.
#
# It isn't used as it seems to cause pexpect to hang.
#
# See
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
# doesn't see the full escape sequence so can miss things.  Hence,
# also stripping out simple control characters.
#
# https://web.archive.org/web/20200805075926/http://ascii-table.com/ansi-escape-sequences.php

class Filter:
    def __init__(self):
        self.stream=sys.stdout.buffer
    def write(self, record):
        #print(record)
        d = record
        # stip out some known escape sequences
        d = re.sub(rb'\x1b\[[0-9;=?]*[HfABCDsuJKmhlr]', b'', d)
        # strip out other non-print characters but leave NL,CR; given
        # well known control characters a name
        d = re.sub(rb'\x00', b'<NUL>', d)
        d = re.sub(rb'[\x01-\x06]', b'', d)
        d = re.sub(rb'[\x07]', b'<BEL>', d)
        d = re.sub(rb'[\x08]', b'<BS>', d)
        d = re.sub(rb'[\x09]', b'<HT>', d)
        # new-line LF [\x0a]
        d = re.sub(rb'[\x0b]', b'<VT>', d)
        d = re.sub(rb'[\x0c]', b'<FF>', d)
        # return   CR [\x0d]
        d = re.sub(rb'[\x0e-\x1a]', b'', d)
        d = re.sub(rb'[\x1b]', b'<ESC>', d)
        d = re.sub(rb'[\x1c-\x1f]', b'', d)
        d = re.sub(rb'[\x7f]', b'<DEL>', d)
        d = re.sub(rb'[\x80-\xff]', b'', d)
        self.stream.write(d);
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
    print("========================================")
    print("   ENGAGING CONTROL CHARACTER SHIELD")
    print("        BLOCKING CHARACTERS")
    print("     THAT MESS WITH THE TERMINAL")
    print("========================================")
else:
    logfile = Raw()

child = pexpect.spawn(command=command[0],
                      args=command[1:],
                      logfile=logfile,
                      echo=False)

os.install_base(child, param)

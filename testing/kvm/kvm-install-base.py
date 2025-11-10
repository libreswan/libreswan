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
from enum import Enum

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

# there must be a python version of this table?
class Char(Enum):
    NUL = 0x00
    BEL = 0x07
    BS  = 0x08
    HT  = 0x09
    LF  = 0x0a
    VT  = 0x0b
    FF  = 0x0c
    CR  = 0x0d
    ESC = 0x1b
    DEL = 0x7f

class State(Enum):
    NORMAL = 1,
    ESCAPE_SEQUENCE = 2,
    PARAMETER = 3,
    INTERMEDIATE = 4,

_parameter = re.compile(rb'[0-9:;<=>?]')
_intermediate = re.compile(rb'[!"#$%&\'()*+,-./]')
_final = re.compile(rb'[\x40-\x7e]')

class Filter:
    def __init__(self):
        self.stream=sys.stdout.buffer
        self.state = State.NORMAL
        self.sequence = b''

    def _putChar(self, char):
        if  char == Char.CR.value or char == Char.LF.value:
            self.stream.write(bytes([char]))
            return
        if char in Char:
            self.stream.write(f'<{Char(char).name}>'.encode())
            return
        if char <= 0x1f or char > 0x7f:
            self.stream.write(f'<{char}>'.encode())
            return
        self.stream.write(bytes([char]));

    def _processChar(self, char):
        # print(self.state, type(char), char)
        byte = bytes([char])
        match self.state:
            case State.NORMAL:
                if char == Char.ESC.value:
                    self.state = State.ESCAPE_SEQUENCE
                    self.sequence = b'<ESC>'
                    return
                self._putChar(char)
                return
            case State.ESCAPE_SEQUENCE:
                # https://en.wikipedia.org/wiki/ANSI_escape_code#Fe_Escape_sequences
                if char == ord('['):
                    # https://en.wikipedia.org/wiki/ANSI_escape_code#Control_Sequence_Introducer_commands
                    self.state = State.PARAMETER
                    self.sequence += byte
                    return
            case State.PARAMETER:
                if _parameter.match(byte):
                    self.sequence += byte
                    return
                if _intermediate.match(byte):
                    self.sequence += byte;
                    self.state = State.INTERMEDIATE
                    return
                if _final.match(byte):
                    self.sequence += byte
                    self.state = State.NORMAL
                    return
            case State.INTERMEDIATE:
                if _intermediate.match(byte):
                    self.sequence += byte
                    return
                if _final.match(byte):
                    self.sequence += byte
                    self.state = State.NORMAL
                    return

        # escape engine failed, dump the sequence and go back to
        # normal
        self.state = State.NORMAL
        self.stream.write(self.sequence)
        self._putChar(char)

    def write(self, record):
        for char in record:
            self._processChar(char)

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

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

# This strips things on the output side.  So that full escape
# sequences are seen it runs a little state machine, ewww!

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
    NORMAL = 1
    # https://en.wikipedia.org/wiki/ANSI_escape_code#Fe_Escape_sequences
    ESCAPE_SEQUENCE = 2
    # https://en.wikipedia.org/wiki/ANSI_escape_code#Control_Sequence_Introducer_commands
    CONTROL_SEQUENCE_INTRODUCER = 3
    CONTROL_SEQUENCE_INTERMEDIATE = 4
    #
    STRING_TERMINATOR = 5

_parameter = re.compile(rb'[0-9:;<=>?]')
_intermediate = re.compile(rb'[!"#$%&\'()*+,-./]')

class EscapeStringSequence(Enum):
    OSC = ord(']')
    ST  = ord('\\')
    DCS = ord('P')
    SOS = ord('X')
    PM  = ord('^')
    APC = ord('_')

class Final(Enum):
    CURSOR_UP = ord('A')
    CURSOR_DOWN = ord('B')
    CURSOR_FORWARD = ord('C')
    CURSOR_BACK = ord('D')
    CURSOR_NEXT_LINE = ord('E')
    CURSOR_PREVIOUS_LINE = ord('F')
    CURSOR_HORIZONTAL_ABSOLUTE = ord('G')
    CURSOR_POSITION = ord('H')

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
                    self.sequence = b''
                    return
                self._putChar(char)
                return

            case State.ESCAPE_SEQUENCE:
                # https://en.wikipedia.org/wiki/ANSI_escape_code#Fe_Escape_sequences
                if char == ord('['):
                    # https://en.wikipedia.org/wiki/ANSI_escape_code#Control_Sequence_Introducer_commands
                    self.state = State.CONTROL_SEQUENCE_INTRODUCER
                    self.sequence += byte
                    return
                if char in EscapeStringSequence:
                    # https://en.wikipedia.org/wiki/ANSI_escape_code#OSC et.al.
                    self.stream.write(b'<')
                    self.stream.write(EscapeStringSequence(char).name.encode());
                    self.stream.write(b'>')
                    self.state = State.NORMAL
                    return

            case State.CONTROL_SEQUENCE_INTRODUCER:
                if _parameter.match(byte):
                    self.sequence += byte
                    return
                if _intermediate.match(byte):
                    self.sequence += byte;
                    self.state = State.CONTROL_SEQUENCE_INTERMEDIATE
                    return
                if char in Final:
                    self.stream.write(b'<')
                    self.stream.write(Final(char).name.encode());
                    self.stream.write(b'>')
                    self.state = State.NORMAL
                    return
                if _final.match(byte):
                    self.sequence += byte
                    self.state = State.NORMAL
                    return
            case State.CONTROL_SEQUENCE_INTERMEDIATE:
                if _intermediate.match(byte):
                    self.sequence += byte
                    return
                if char in Final:
                    self.stream.write(b'<')
                    self.stream.write(Final(char).name.encode());
                    self.stream.write(b'>')
                    self.state = State.NORMAL
                    return
                if _final.match(byte):
                    self.sequence += byte
                    self.state = State.NORMAL
                    return

        # escape engine failed, dump the sequence and go back to
        # normal
        self.state = State.NORMAL
        self.stream.write(b'<ESC>')
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

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
from enum import auto

from platform import alpine
from platform import debian
from platform import fedora
from platform import linux
from platform import freebsd
from platform import netbsd
from platform import openbsd

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
    SOH = 0x01
    STX = 0x02
    ETX = 0x03
    EOT = 0x04
    ENQ = 0x05
    ACK = 0x06
    BEL = 0x07
    BS  = 0x08, True
    HT  = 0x09, True
    LF  = 0x0a, True
    VT  = 0x0b, True
    FF  = 0x0c, True
    CR  = 0x0d, True
    SO  = 0x0e, True
    SI  = 0x0f, True
    DLE = 0x10
    DC1 = 0x11
    DC2 = 0x12
    DC3 = 0x13
    DC4 = 0x14
    NAK = 0x15
    SYN = 0x16
    ETB = 0x17
    CAN = 0x18
    EM  = 0x19
    SUB = 0x1a
    ESC = 0x1b
    FS  = 0x1c
    GS  = 0x1d
    RS  = 0x1e
    US  = 0x1f
    DEL = 0x7f
    def __new__(cls, value, ok=False):
        obj = object.__new__(cls)
        obj._value_ = value
        return obj
    def __init__(self, value, ok=False):
        self.byte = bytes([value])
        self.safe = (ok and self.byte or f'<{self.name}>'.encode())

class State(Enum):
    NORMAL = auto()
    # https://en.wikipedia.org/wiki/ANSI_escape_code#Fe_Escape_sequences
    ESCAPE_SEQUENCE = auto()
    # https://en.wikipedia.org/wiki/ANSI_escape_code#Control_Sequence_Introducer_commands
    CONTROL_SEQUENCE_INTRODUCER = auto()
    CONTROL_SEQUENCE_INTERMEDIATE = auto()
    # https://en.wikipedia.org/wiki/ISO/IEC_2022#Character_set_designations
    CHARACTER_SET = auto()
    #
    STRING_TERMINATOR = auto()


# https://en.wikipedia.org/wiki/ANSI_escape_code#OSC
class EscapeStringSequence(Enum):
    OSC = ord(']')
    ST  = ord('\\')
    DCS = ord('P')
    SOS = ord('X')
    PM  = ord('^')
    APC = ord('_')
    # linux stuff see console_codes(4)
    RIS = ord('c')
    IND = ord('D')
    NEL = ord('E')
    HTS = ord('H')
    RI = ord('M')
    DECID = ord('Z')
    DECSC = ord('7')
    DECCR = ord('8')
    DECPNM = ord('>')
    DECPAM = ord('=')

# https://en.wikipedia.org/wiki/ANSI_escape_code#Control_Sequence_Introducer_commands
_control_sequence_parameter = re.compile(rb'[0-9:;<=>?]')
_control_sequence_intermediate = re.compile(rb'[!"#$%&\'()*+,-./]')
_control_sequence_final = re.compile(rb'[\x40-\x7e]')

# Entries in this table are acceptable and passed through.
class ControlSequenceFinalByte(Enum):
    CURSOR_UP = ord('A')
    CURSOR_DOWN = ord('B')
    CURSOR_FORWARD = ord('C')
    CURSOR_BACK = ord('D')
    CURSOR_NEXT_LINE = ord('E')
    CURSOR_PREVIOUS_LINE = ord('F')
    CURSOR_HORIZONTAL_ABSOLUTE = ord('G')
    CURSOR_POSITION = ord('H')
    ERASE_DISPLAY = ord('J')
    ERASE_LINE = ord('K')
    INSERT_BLANK_LINES = ord('L')
    DELETE_BLANK_LINES = ord('M')
    DELETE_CHARACTERS = ord('P')
    ERASE_CHARACTERS = ord('X')

# https://en.wikipedia.org/wiki/ISO/IEC_2022#Character_set_designations
_character_set_intermediate = re.compile(rb'[\x20-\x2f]')
_character_set_final = re.compile(rb'[\x30-\x7e]')

class Filter:
    def __init__(self):
        self.stream=sys.stdout.buffer
        self.state = State.NORMAL
        self.sequence = b''

    def _putChar(self, char):
        if char <= 0x1f:
            self.stream.write(Char(char).safe)
            return
        if char > 0x7f:
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
                if _character_set_intermediate.match(byte):
                    # https://en.wikipedia.org/wiki/ISO/IEC_2022#Character_set_designations
                    self.state = State.CHARACTER_SET
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
                if _control_sequence_parameter.match(byte):
                    self.sequence += byte
                    return
                if _control_sequence_intermediate.match(byte):
                    self.sequence += byte
                    self.state = State.CONTROL_SEQUENCE_INTERMEDIATE
                    return
                if char in ControlSequenceFinalByte:
                    #self.stream.write(b'<')
                    #self.stream.write(ControlSequenceFinalByte(char).name.encode());
                    #self.stream.write(b'>')
                    self.sequence += byte
                    self.stream.write(Char.ESC.byte + self.sequence)
                    self.state = State.NORMAL
                    return
                if _control_sequence_final.match(byte):
                    self.sequence += byte
                    self.state = State.NORMAL
                    return
            case State.CONTROL_SEQUENCE_INTERMEDIATE:
                if _control_sequence_intermediate.match(byte):
                    self.sequence += byte
                    return
                if char in ControlSequenceFinalByte:
                    #self.stream.write(b'<')
                    #self.stream.write(ControlSequenceFinalByte(char).name.encode());
                    #self.stream.write(b'>')
                    self.sequence += byte
                    self.stream.write(Char.ESC.byte + self.sequence)
                    self.state = State.NORMAL
                    return
                if _control_sequence_final.match(byte):
                    self.sequence += byte
                    self.state = State.NORMAL
                    return

            case State.CHARACTER_SET:
                if _character_set_intermediate.match(byte):
                    self.sequence += byte
                    return
                if _character_set_final.match(byte):
                    self.sequence += byte
                    #self.stream.write(b"<nF>")
                    self.state = State.NORMAL
                    return

        # escape engine failed, dump the sequence and go back to
        # normal
        self.state = State.NORMAL
        self.stream.write(b'<ESC')
        self.stream.write(self.sequence)
        self._putChar(char)
        self.stream.write(b'>')

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

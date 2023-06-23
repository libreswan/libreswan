#!/usr/bin/env python3

# Script to install fedora domain
#
# Copyright (C) 2021 Andrew Cagney
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

command = sys.argv[1:]
print("command", command)

#see https://web.archive.org/web/20200805075926/http://ascii-table.com/ansi-escape-sequences.php
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

child = pexpect.spawn(command=command[0],
                      args=command[1:],
                      logfile=sys.stdout.buffer,
                      echo=False)

# two ways to manipulate the output from command
# wrap child.read_nonblocking()
child._decoder = AsciiDecoder() # used by SpawnBase.read_nonblocking()

child.expect([pexpect.EOF], timeout=None, searchwindowsize=1)
sys.exit(child.wait())

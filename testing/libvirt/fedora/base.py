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

command = sys.argv[1:]
print("command", command)

class LogFilter:
    def __init__(self):
        self.stream=sys.stdout.buffer
    def write(self, record):
        self.stream.write(record.replace(b'\33', b''))
    def flush(self):
        self.stream.flush()

child = pexpect.spawn(command=command[0],
                      args=command[1:],
                      logfile=LogFilter(),
                      echo=False)
child.expect([pexpect.EOF], timeout=None, searchwindowsize=1)
sys.exit(child.wait())

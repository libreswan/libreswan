#!/usr/bin/env python3

# pexpect script to install Alpine base Domain
#
# Copyright (C) 2023 Andrew Cagney
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

import pexpect
import sys
import time
import os

FILTER_OUTPUT = True

def i(child):
    '''go interactive then quit'''
    child.logfile = None
    child.interact()
    sys.exit(0)

def rs(child, r, s):
    child.expect(r, timeout=None)
    for c in s:
        child.send(c)

def c(child, s):
    child.expect('\n# ', timeout=None)
    time.sleep(1)
    for c in s:
        child.send(c)
    child.send('\n')

# boot in single user mode (/ is RO)

def install_base(child, param):

    #i(child)
    #sys.exit(child.wait())

    print("waiting on child");
    child.expect([pexpect.EOF], timeout=None, searchwindowsize=1)
    sys.exit(child.wait())

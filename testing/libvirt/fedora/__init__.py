#!/usr/bin/env python3

# Script to install fedora domain
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

import pexpect
import sys

FILTER_OUTPUT = False

def i(child):
    '''go interactive then quit'''
    child.logfile = None
    child.interact()
    sys.exit(0)

def install_base(child, param):

    print("waiting on child");
    child.expect([pexpect.EOF], timeout=None, searchwindowsize=1)
    sys.exit(child.wait())

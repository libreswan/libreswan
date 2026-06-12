#!/usr/bin/env python3

# pexpect script to Install FreeBSD base Domain
#
# Copyright (C) 2021-2023 Andrew Cagney
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
import os

FILTER_OUTPUT = True

def install_base(child, param):

    # XXX: how to fix this? scribble on /etc/rc.local?
    print("waiting for terminal type")
    child.expect("terminal type", timeout=None)
    print("hitting default")
    child.send("\n")

    child.expect([pexpect.EOF, "uhub0: detached"], timeout=None, searchwindowsize=20)
    os.system('sudo virsh destroy ' + param.domain + ' > /dev/null')
    child.wait()
    sys.exit(0)

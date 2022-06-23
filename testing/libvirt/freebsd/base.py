#!/usr/bin/env python3

# pexpect script to Install FreeBSD base Domain
#
# Copyright (C) 2021-2022 Andrew Cagney
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
import time
import os

domain = os.getenv("DOMAIN")
gateway = os.getenv("GATEWAY")
pooldir = os.getenv("POOLDIR")
command = sys.argv[1:]

print("domain", domain)
print("gateway", gateway)
print("pooldir", pooldir)
print("command", command)

child = pexpect.spawn(command[0], command[1:], logfile=sys.stdout.buffer, echo=False)

def i():
    '''go interactive then quit'''
    child.logfile = None
    child.interact()
    sys.exit(0)

def rs(r, s):
    '''expect R then send S'''
    child.expect(r, timeout=None)
    for c in s:
        child.send(c)

def c(s):
    child.expect('\n# ')
    time.sleep(1)
    for c in s:
        child.send(c)
    child.send('\n')

# XXX: how to fix this? scribble on /etc/rc.local?
rs("Console type", "\n")

m = child.expect([pexpect.EOF, "uhub0: detached"], timeout=None, searchwindowsize=20)
os.system('sudo virsh destroy ' + domain + ' > /dev/null')
child.wait()
sys.exit(0)

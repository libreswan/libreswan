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

command = sys.argv[1:]
print("command", command)

domain = "@@DOMAIN@@"
gateway = "@@GATEWAY@@"
pooldir = "@@POOLDIR@@"
benchdir = "@@BENCHDIR@@"

print("domain", domain)
print("gateway", gateway)
print("pooldir", pooldir)
print("benchdir", benchdir)

class LogFilter:
    def __init__(self):
        self.stream=sys.stdout.buffer
    def write(self, record):
        self.stream.write(record.replace(b'\33', b''))
    def flush(self):
        self.stream.flush()

child = pexpect.spawn(command=command[0], args=command[1:],
                      logfile=LogFilter(),
                      echo=False)

def i():
    '''go interactive then quit'''
    child.logfile = None
    child.interact()
    sys.exit(0)

def rs(r, s):
    child.expect(r, timeout=None)
    for c in s:
        child.send(c)

rs('login: ', 'root\n')

# run alpine's setup script; change this to an answer file or add -q?

rs('# ', 'setup-alpine\n');
rs('Enter system hostname', 'alpine\n')
rs('Available interfaces are: eth0', '')
rs('Which one do you want to initialize', 'eth0\n')
rs('Ip address for eth0', 'dhcp\n')
rs('Do you want to do any manual network configuration', 'n\n')
rs('New password: ', 'swan\n')
rs('Retype password: ', 'swan\n')
rs('Which timezone are you in', 'UTC\n')
rs('HTTP/FTP proxy URL', 'none\n')
rs('Available mirrors:', '')
rs('--More--', 'q')
rs('Enter mirror number', '1\n')
rs('Setup a user', 'no\n')
rs('Which ssh server', 'none\n')
rs('Which disk', 'vda\n')
rs('How would you like to use it', 'sys\n')
rs('Erase the above disk', 'y\n')
rs('Installation is complete. Please reboot.', '')

# Now hack the new rootfs

rs('# ', 'mount /dev/vda3 /mnt\n')
rs('# ', 'chroot /mnt\n')

# fix the prompt

rs('# ', 'echo PS1=\\\'\'[\\u@\\h \\w $(echo $?)]\\$ \'\\\' | tee /root/.profile\n')
rs('# ', 'cat /root/.profile\n')

# setup NFS mounts of test directories

rs('# ', 'echo '+gateway+':'+pooldir+' /pool nfs rw | tee -a /etc/fstab\n')
rs('# ', 'echo '+gateway+':'+benchdir+' /bench nfs rw | tee -a /etc/fstab\n')
rs('# ', 'cat /etc/fstab\n')
rs('# ', 'mkdir -p /pool /bench\n')

rs('# ', 'apk add nfs-utils\n')
rs('# ', 'rc-update add nfsmount\n')

rs('# ', 'poweroff\n')

sys.exit(child.wait())

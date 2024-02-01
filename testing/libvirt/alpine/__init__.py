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

def rs(child, r, s):
    child.expect(r, timeout=None)
    for c in s:
        child.send(c)

def install_base(child, param):

    rs(child, 'login: ', 'root\n')

    # run alpine's setup script; change this to an answer file or add -q?

    rs(child, '# ', 'setup-alpine\n');
    rs(child, 'Enter system hostname', 'alpine\n')
    rs(child, 'Available interfaces are: eth0', '')
    rs(child, 'Which one do you want to initialize', 'eth0\n')
    rs(child, 'Ip address for eth0', 'dhcp\n')
    rs(child, 'Do you want to do any manual network configuration', 'n\n')
    rs(child, 'New password: ', 'swan\n')
    rs(child, 'Retype password: ', 'swan\n')
    rs(child, 'Which timezone are you in', 'UTC\n')
    rs(child, 'HTTP/FTP proxy URL', 'none\n')
    rs(child, 'Enter mirror number or URL:', '1\n')
    rs(child, 'Setup a user', 'no\n')
    rs(child, 'Which ssh server', 'none\n')
    rs(child, 'Which disk', 'vda\n')
    rs(child, 'How would you like to use it', 'sys\n')
    rs(child, 'Erase the above disk', 'y\n')
    rs(child, 'Installation is complete. Please reboot.', '')

    # Now hack the new rootfs

    rs(child, '# ', 'mount /dev/vda3 /mnt\n')
    rs(child, '# ', 'chroot /mnt\n')

    # fix the prompt

    rs(child, '# ', 'echo PS1=\\\'\'[\\u@\\h \\w $(echo $?)]\\$ \'\\\' | tee /root/.profile\n')
    rs(child, '# ', 'cat /root/.profile\n')

    # setup NFS mounts of test directories

    rs(child, '# ', 'echo '+param.gateway+':'+param.pooldir+' /pool nfs rw | tee -a /etc/fstab\n')
    rs(child, '# ', 'echo '+param.gateway+':'+param.benchdir+' /bench nfs rw | tee -a /etc/fstab\n')
    rs(child, '# ', 'cat /etc/fstab\n')
    rs(child, '# ', 'mkdir -p /pool /bench\n')

    rs(child, '# ', 'apk add nfs-utils\n')
    rs(child, '# ', 'rc-update add nfsmount\n')

    rs(child, '# ', 'poweroff\n')

    sys.exit(child.wait())

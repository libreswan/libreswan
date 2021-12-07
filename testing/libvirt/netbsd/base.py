#!/usr/bin/env python3

# pexpect script to Install NetBSD base Domain
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

import pexpect
import sys
import time

#argv[0]
domain = sys.argv[1]
gateway = sys.argv[2]
pooldir = sys.argv[3]
command = sys.argv[6:]

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
    child.expect(r)
    for c in s:
        child.send(c)

def c(s):
    child.expect('\n# ')
    time.sleep(1)
    for c in s:
        child.send(c)
    child.send('\n')

# boot in single user mode (/ is RO)

rs('seconds', '2')
rs('Enter pathname of shell or RETURN for /bin/sh:', '\n')
# the above has only 4 seconds
#io('Terminal type.*: ', 'vt100')
#io('a: Installation messages in English', 'a')
#io('x: Exit Install System', 'x')

# tmp writeable

c('mount -t tmpfs tmpfs /tmp')
c('touch /tmp/foo')

# Initialize the disk creating a single DOS NetBSD partition.

c('dd count=2 if=/dev/zero of=/dev/ld0')
c('fdisk -f -i ld0')
c('fdisk -f -0 -a -s 169 -u ld0')
c('fdisk ld0')

# Now create the NetBSD partitions within that.
#
# By default NetBSD generates a label with everything in e:, switch it
# to a:.  And use that as the root file system.  Don't bother with
# swap.

c('disklabel ld0 > /tmp/ld0.label')
c('sed -i -e "s/ e:/ a:/" /tmp/ld0.label')
c('disklabel -R -r ld0 /tmp/ld0.label')
c('newfs /dev/ld0a')

# Enable booting of the first (0) partition.
#
# The MBR is installed into front of the disk; the NetBSD partition is
# made active; and finally install secondary boot and boot-blocks are
# installed into the just built root file system.
#
# Should (can) speed be changed, 9600 is so retro?

c('fdisk -f -0 -a ld0')
c('fdisk -f -c /usr/mdec/mbr_com0 ld0')
c('mount -o async /dev/ld0a /targetroot')
c('cp /usr/mdec/boot /targetroot/boot') # to / not /boot/
c('umount /targetroot')
c('dumpfs /dev/ld0a | grep format') # expect FFSv1
c('installboot -v -o console=com0,timeout=5,speed=9600 /dev/rld0a /usr/mdec/bootxx_ffsv1')

# Unpack the files into the root file system.

c('mount -o async /dev/ld0a /targetroot')
c('touch /targetroot/.')
c('cd /targetroot')
c('mount -rt cd9660 /dev/cd1 /mnt')
c('for f in /mnt/i386/binary/sets/[a-jl-z]*.tgz ; do echo $f ; tar xpf $f || break ; done')
c('tar xpf /mnt/i386/binary/sets/kern-GENERIC.tgz')
c('cd /')

# Configure the system

c('chroot /targetroot')

# also blank out TOOR's password as backup
# c("echo swan | pwhash |sed -e 's/[\$\/\\]/\\\$/g' | tee /tmp/pwd")
# c('sed -i -e "s/root:[^:]*:/root:$(cat /tmp/pwd):/"  /etc/master.passwd')
# c('sed -i -e "s/toor:[^:]*:/toor::/"  /etc/master.passwd')

c('mkdir -p /kern /proc')
c('echo "ROOT.a          /               ffs     rw,noatime      1 1" >> /etc/fstab')
c('echo "kernfs          /kern           kernfs  rw"                  >> /etc/fstab')
c('echo "ptyfs           /dev/pts        ptyfs   rw"                  >> /etc/fstab')
c('echo "procfs          /proc           procfs  rw"                  >> /etc/fstab')
c('echo "tmpfs           /var/shm        tmpfs   rw,-m1777,-sram%25"  >> /etc/fstab')
c('echo "tmpfs           /tmp            tmpfs   rw"                  >> /etc/fstab')

pool = gateway + ":" + pooldir
c('mkdir /pool')
c('echo "'+pool+'        /pool           nfs     rw"                  >> /etc/fstab')

# booting

c('echo rc_configured=YES >> /etc/rc.conf')
c('echo hostname=netbsd   >> /etc/rc.conf')
c('echo no_swap=YES       >> /etc/rc.conf')
c('echo savecore=NO       >> /etc/rc.conf')
c('echo dhcpcd=YES        >> /etc/rc.conf')

# packages

c('echo PKG_PATH=https://cdn.NetBSD.org/pub/pkgsrc/packages/NetBSD/i386/9.2/All > /etc/pkg_install.conf')

# TODO:
#
# - install needed packages:
#   https://libreswan.org/wiki/Building_and_installing_from_source
#
# - configure NFS mounts
#   host is exporting testing/ need to export root/
#   need to specify ipaddress and path
#
# - ?

# all done

c('exit')
c('umount /targetroot')
c('poweroff')

sys.exit(child.wait())
i()


# OTHER STUFF

io('a: Install NetBSD to hard disk', 'a')

io('You have chosen to install NetBSD on your hard disk', 'b')

io('partition>', 'a')
io('Filesystem type', '4.4BSD')
io('Start offset', '0c')
io('Partition size', '$')
io('partition>', 'P')
io('partition>', 'W')
io('Label disk', '')
io('partition>', 'Q')

io('a: ld0', 'a')
io('a: This is the correct geometry', 'a')
io('a: Use existing GPT partitions', 'a')
io('x: Partition sizes ok', 'x')

io('Ok, we are now ready to install NetBSD on your hard disk', 'b')
io('Hit enter to continue', '')

io('Selected bootblock: Serial port com0 at 9600 baud', 'x')
io('a: Full installation', 'a')

io('f: Unmounted fs', 'f')
io('a: Device', 'acd1')
io('b: File system', 'bcd9660')
io('x: Continue', 'x')

i()

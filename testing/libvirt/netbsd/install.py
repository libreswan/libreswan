#!/usr/bin/env python3

# Possibly useful reference:
# http://meta.libera.cc/2020/12/quick-netbsd-serial-console-install-on.html

import pexpect
import sys
import time

domain = sys.argv[1]
virtinstall = " ".join(str(arg) for arg in sys.argv[2:])
print("domain", domain)
print("virtinstall", virtinstall)

def i():
    child.logfile = None
    child.interact()
    sys.exit(0)

def rs(r, s):
    child.expect(r)
    time.sleep(1)
    for c in s:
        child.send(c)

def io(r, s):
    child.expect(r)
    time.sleep(1)
    for c in s:
        child.send(c)
    child.send('\n')

child = pexpect.spawn(virtinstall, logfile=sys.stdout.buffer, echo=False)

# how to skip this part and go directly to the console?
io('seconds', '')

io('Terminal type.*: ', 'vt100')
io('a: Installation messages in English', 'a')

# use the console directly

io('x: Exit Install System', 'x')

# install the DOS partition, make certain that the disk is invalid.

io('# ', 'dd count=2 if=/dev/zero of=/dev/ld0')
io('# ', 'fdisk -f -i ld0')
io('# ', 'fdisk -f -c /usr/mdec/mbr_com0_9600 ld0')
io('# ', 'fdisk -f -0 -a -s 169 -u ld0')
io('# ', 'fdisk ld0')

# Create the NetBSD partition.  By default NetBSD generates a label
# with everything in e:, switch it to a:.

io('# ', 'disklabel ld0 > /tmp/ld0.label')
io('# ', 'sed -i -e "s/ e:/ a:/" /tmp/ld0.label')
io('# ', 'disklabel -R -r ld0 /tmp/ld0.label')

# Format/mount the disk

io('# ', 'newfs /dev/ld0a')

# Set up the boot for serial port

io('# ', 'mount /dev/ld0a /targetroot')
io('# ', 'cp /usr/mdec/boot /targetroot/boot') # to / not /boot/
io('# ', 'umount /targetroot')
io('# ', 'dumpfs /dev/ld0a | grep format') # expect FFSv1
io('# ', 'installboot -v -o console=com0,timeout=5,speed=9600 /dev/rld0a /usr/mdec/bootxx_ffsv1')

# Unpack the disks

io('# ', 'mount /dev/ld0a /targetroot')
io('# ', 'cd /targetroot')
io('# ', 'mount -rt cd9660 /dev/cd1 /mnt')
io('# ', 'for f in /mnt/i386/binary/sets/[a-jl-z]*.tgz ; do echo $f ; tar xpf $f ; done')
io('# ', 'tar xpf /mnt/i386/binary/sets/kern-GENERIC.tgz')
io('# ', 'cd /')

# Configure the system

io('# ', 'chroot /targetroot')

# also blank out TOOR's password as backup
# io('# ', "echo swan | pwhash |sed -e 's/[\$\/\\]/\\\$/g' | tee /tmp/pwd")
# io('# ', 'sed -i -e "s/root:[^:]*:/root:$(cat /tmp/pwd):/"  /etc/master.passwd')
# io('# ', 'sed -i -e "s/toor:[^:]*:/toor::/"  /etc/master.passwd')

io('# ', 'echo PKG_PATH=https://cdn.NetBSD.org/pub/pkgsrc/packages/NetBSD/i386/9.2/All > /etc/pkg_install.conf')

io('# ', 'mkdir -p /kern /proc')
io('# ', 'echo "ROOT.a          /               ffs     rw,noatime      1 1" >> /etc/fstab')
io('# ', 'echo "kernfs          /kern           kernfs  rw"                  >> /etc/fstab')
io('# ', 'echo "ptyfs           /dev/pts        ptyfs   rw"                  >> /etc/fstab')
io('# ', 'echo "procfs          /proc           procfs  rw"                  >> /etc/fstab')
io('# ', 'echo "tmpfs           /var/shm        tmpfs   rw,-m1777,-sram%25"  >> /etc/fstab')
io('# ', 'echo "tmpfs           /tmp            tmpfs   rw"                  >> /etc/fstab')
io('# ', 'mount -a')

io('# ', 'echo rc_configured=YES >> /etc/rc.conf')
io('# ', 'echo hostname=netbsd   >> /etc/rc.conf')
io('# ', 'echo no_swap=YES       >> /etc/rc.conf')
io('# ', 'echo savecore=NO       >> /etc/rc.conf')
io('# ', 'echo dhcpcd=YES        >> /etc/rc.conf')

# all done

# io('# ', 'poweroff')

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

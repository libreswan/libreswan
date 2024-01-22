#!/bin/sh

set -x

:
: Controlled panic
:

sysctl -w ddb.onpanic=0
sysctl -w ddb.lines=0

:
: Make /tmp writable.
:

mount -t tmpfs tmpfs /tmp
touch /tmp/foo

:
: Initialize the disk creating a single DOS NetBSD partition.
:

dd count=2 if=/dev/zero of=/dev/ld0
fdisk -f -i ld0
fdisk -f -0 -a -s 169 -u ld0
fdisk ld0

:
: Now create the NetBSD partitions within that.
:

# By default NetBSD generates a label with everything in e:, switch it
# to a:.  And use that as the root file system.  Don't bother with
# swap.

disklabel ld0 > /tmp/ld0.label || echo disklabel barfed 2
sed -i -e "s/ e:/ a:/" /tmp/ld0.label
disklabel -R -r ld0 /tmp/ld0.label
newfs /dev/ld0a

:
: Enable booting of the first or zero partition.
:

# The MBR is installed into front of the disk; the NetBSD partition is
# made active; and finally install secondary boot and boot-blocks are
# installed into the just built root file system.
#
# Should (can) speed be changed, 9600 is so retro?

fdisk -f -0 -a ld0
fdisk -f -c /usr/mdec/mbr_com0 ld0
mount -o async /dev/ld0a /targetroot
cp /usr/mdec/boot /targetroot/boot # file: /boot not /boot/
umount /targetroot
dumpfs /dev/ld0a | grep format # expect FFSv1
installboot -v -o console=com0,timeout=5,speed=9600 /dev/rld0a /usr/mdec/bootxx_ffsv1

:
: Unpack the files into the root file system.
:

mount -o async /dev/ld0a /targetroot
touch /targetroot/.

sets=/mnt/$(uname -m)/binary/sets

case $(uname -m) in
    i386 ) tgz=tgz ;;
    * ) tgz=tar.xz ;;
esac

ls ${sets}
for f in ${sets}/[a-jl-z]*.${tgz} ${sets}/[a-jl-z]*.${tgz} ; do
    if test -r "${f}" ; then
	echo $f
	( cd /targetroot && tar xpf ${f} )
    fi
done

# Generating the ISO seems to, sometimes, corrupt the name.
for f in kern-GENERIC.${tgz} kern_generic.${tgz} ; do
    k=${sets}/${f}
    if test -r ${k} ; then
	( cd /targetroot && tar xpvf ${k} )
	break
    fi
done


:
: Set up the mount points
:

mkdir /targetroot/kern /targetroot/proc /targetroot/pool /targetroot/bench

cat <<EOF | tee /targetroot/etc/fstab
ROOT.a          /               ffs     rw,noatime      1 1
kernfs          /kern           kernfs  rw
ptyfs           /dev/pts        ptyfs   rw
procfs          /proc           procfs  rw
tmpfs           /var/shm        tmpfs   rw,-m1777,-sram%25
tmpfs           /tmp            tmpfs   rw
@@GATEWAY@@:@@POOLDIR@@ /pool   nfs     rw
@@GATEWAY@@:@@BENCHDIR@@ /bench nfs     rw
EOF


:
: run post install
:

# opensslcertsrehash needs /dev populated
( cd /targetroot/dev && ./MAKEDEV all )
# postinstall needs these
cp ${sets}/etc.${tgz} /targetroot/var/tmp
cp ${sets}/xetc.${tgz} /targetroot/var/tmp
# opensslcertsreahsh only works with /
chroot /targetroot postinstall -s /var/tmp/etc.${tgz} -s /var/tmp/xetc.${tgz} fix


# also blank out TOOR's password as backup?
# c("echo swan | pwhash |sed -e 's/[\$\/\\]/\\\$/g' | tee /tmp/pwd")
# sed -i -e "s/root:[^:]*:/root:$(cat /tmp/pwd):/"  /etc/master.passwd
# sed -i -e "s/toor:[^:]*:/toor::/"  /etc/master.passwd

:
: Setup the network to use DHCP on eth0
:

cat <<EOF | tee -a /targetroot/etc/rc.conf
. /etc/defaults/rc.conf
rc_configured=YES
no_swap=YES
savecore=NO
EOF

cat <<EOF | tee /targetroot/etc/ifconfig.vioif0
dhcp
EOF

cat <<EOF | tee /targetroot/etc/myname
netbsd
EOF

:
: Fix SHELL prompt
:

#
# Change the shell prompt to [USER@HOST PWD STATUS]# so it works with
# the make files.
#

cat <<EOF | tee /targetroot/root/.shrc
case "\$-" in
     *i*)
	if /bin/test -z "\${HOST}"; then
	   HOST=\$(hostname)
	fi
	set -E emacs
	set -o tabcomplete
	set -o promptcmds
	PS1='['"\${USER}@\${HOST%%.*}"' \$(s=\$?;p=\${PWD##*/};echo \${p:-/} \${s#0})]# '
        ;;
esac
EOF

:
: tweak sysctl
:

echo ddb.lines=0 >> /targetroot/etc/sysctl.conf

:
: Cleanup and shutdown
:

umount /targetroot
umount /mnt

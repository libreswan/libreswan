#!/bin/sh

set -x

mount -t tmpfs tmpfs /tmp
touch /tmp/foo

# Initialize the disk creating a single DOS NetBSD partition.

dd count=2 if=/dev/zero of=/dev/ld0
fdisk -f -i ld0
fdisk -f -0 -a -s 169 -u ld0
fdisk ld0

# Now create the NetBSD partitions within that.
#
# By default NetBSD generates a label with everything in e:, switch it
# to a:.  And use that as the root file system.  Don't bother with
# swap.

disklabel ld0 > /tmp/ld0.label
sed -i -e "s/ e:/ a:/" /tmp/ld0.label
disklabel -R -r ld0 /tmp/ld0.label
newfs /dev/ld0a

# Enable booting of the first (0) partition.
#
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

# Unpack the files into the root file system.

mount -o async /dev/ld0a /targetroot
touch /targetroot/.
cd /targetroot

ls /mnt/i386/binary/sets/
for f in /mnt/i386/binary/sets/[a-jl-z]*.tgz ; do echo $f ; tar xpf $f || break ; done
# renamed to kern_generic, and then back to kern-GENERIC
tar xpf /mnt/i386/binary/sets/kern-GENERIC.tgz
cd /

# Configure the system

# also blank out TOOR's password as backup?
# c("echo swan | pwhash |sed -e 's/[\$\/\\]/\\\$/g' | tee /tmp/pwd")
# sed -i -e "s/root:[^:]*:/root:$(cat /tmp/pwd):/"  /etc/master.passwd
# sed -i -e "s/toor:[^:]*:/toor::/"  /etc/master.passwd

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

# booting

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

# Change the shell prompt to [USER@HOST PWD STATUS]#

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

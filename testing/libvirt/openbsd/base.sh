#!/bin/sh

set -x

# Start iked daemon by default on boot
echo 'iked_flags=""' >> /mnt/etc/rc.conf.local

# try to fix powerdown; works for /mnt, not for /, ulgh!
echo powerdown=YES >>     /etc/rc.powerdown
echo powerdown=YES >> /mnt/etc/rc.powerdown

echo '====> Zapping rc.firsttime <===='

rm /mnt/etc/rc.firsttime

echo '====> Mounting /pool <===='

mkdir -p /mnt/pool
cat <<EOF | tee -a /mnt/etc/fstab
@@GATEWAY@@:@@POOLDIR@@ /pool nfs rw,tcp 0 0
EOF

echo '====> also unpack sources <===='

mount /dev/cd0c /mnt2
cd /mnt/usr/src
tar xzf /mnt2/src.tar.gz
tar xzf /mnt2/sys.tar.gz
cd /
umount /mnt2

# Tweak the (korn) shell prompt et.al.

cat <<EOF | tee /mnt/root/.profile
export PATH=/sbin:/usr/sbin:/bin:/usr/bin:/usr/X11R6/bin:/usr/local/sbin:/usr/local/bin

export PKG_CACHE=/pool/pkg.openbsd
export PKG_PATH=${PKG_CACHE}:installpath

case "\$-" in
     *i* )
         set -o emacs
         set -o csh-history
	 PS1='[\u@\h \W \$(echo \$?)]\\\$ '
	 ;;
esac
EOF

#!/bin/sh

set -x

# Hobble some daemons
cat <<EOF | tee /mnt/etc/rc.conf.local
iked_flags=NO
sshd_flags=NO
cron_flags=NO
EOF

# try to fix powerdown; works for /mnt, not for /, ulgh!
echo powerdown=YES >>     /etc/rc.powerdown
echo powerdown=YES >> /mnt/etc/rc.powerdown

echo '====> Zapping rc.firsttime <===='

rm /mnt/etc/rc.firsttime

echo '====> Mounting /pool <===='

mkdir -p /mnt/pool /mnt/bench
cat <<EOF | tee -a /mnt/etc/fstab
@@GATEWAY@@:@@POOLDIR@@  /pool  nfs rw,tcp 0 0
@@GATEWAY@@:@@BENCHDIR@@ /bench nfs rw,tcp 0 0
EOF

# Tweak the (korn) shell prompt et.al.

cat <<EOF | tee /mnt/root/.profile
export PATH=/sbin:/usr/sbin:/bin:/usr/bin:/usr/X11R6/bin:/usr/local/sbin:/usr/local/bin

export PKG_CACHE=/pool/pkg.openbsd.\$(uname -r)
export PKG_PATH=${PKG_CACHE}:installpath

case "\$-" in
     *i* )
         set -o emacs
         set -o csh-history
	 PS1='[\u@\h \W \$(echo \$?)]\\\$ '
	 ;;
esac
EOF

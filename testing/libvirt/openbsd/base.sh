#!/bin/sh

set -x

# Save the config files

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

cat <<EOF | tee /mnt/root/.profile
PATH=/sbin:/usr/sbin:/bin:/usr/bin:/usr/X11R6/bin:/usr/local/sbin:/usr/local/bin
export PATH
case "\$-" in
     *i* )
	 PS1='[\u@\h \W \$(echo \$?)]\\\$ '
	 ;;
esac
EOF

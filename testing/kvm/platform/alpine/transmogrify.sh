#!/bin/sh

set -xe ; exec < /dev/null

# update /etc/fstab with current /source and /testing

mkdir -p /source /testing
sed -e '/bench/d' /etc/fstab > /tmp/fstab

cat <<EOF >> /tmp/fstab
source   /source         9p     rw	0 0
testing  /testing        9p     rw	0 0
pool     /pool           9p     rw	0 0
EOF

mv /tmp/fstab /etc/fstab
cat /etc/fstab

# enable static routes

touch /etc/route.conf
rc-update add staticroute

# Replace the HOSTNAME init script with one that can figure out the
# HOSTNAME and interface configuration based on interfaces (it saves
# the result in /etc/network/interfaces and /etc/route.conf.

cp -v /bench/testing/kvm/platform/alpine/hostname.sh /etc/init.d/hostname
chmod a+x /etc/init.d/hostname
cp -v /bench/testing/kvm/rc.d/rc.hostname /etc/rc.hostname

# chsh -s /bin/bash root
sed -i -e 's,root:/bin/.*,root:/bin/bash,' /etc/passwd

for f in /bench/testing/kvm/root/[a-z]* ; do
    cp -v ${f} /root/.$(basename $f)
done

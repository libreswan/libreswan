#!/bin/sh

set -xe ; exec < /dev/null

GATEWAY=@@GATEWAY@@
PREFIX=@@PREFIX@@
BENCHDIR=@@BENCHDIR@@
POOLDIR=@@POOLDIR@@
SOURCEDIR=@@SOURCEDIR@@
TESTINGDIR=@@TESTINGDIR@@

# update /etc/fstab with current /source and /testing

mkdir -p /pool /source /testing
sed -i -e '/source/d' -e '/testing/d' /etc/fstab
cat <<EOF | tee -a /etc/fstab
${GATEWAY}:${SOURCEDIR}   /source   nfs  rw,tcp
${GATEWAY}:${TESTINGDIR}  /testing  nfs  rw,tcp
EOF

cp -v /bench/testing/kvm/openbsd/rc.conf.local /etc/rc.conf.local
chmod a+r /etc/rc.conf.local

cp -v /bench/testing/kvm/rc.d/rc.local /etc/
chmod a+x /etc/rc.local

chsh -s /usr/local/bin/bash root

for f in /bench/testing/kvm/root/[a-z]* ; do
    cp -v ${f} /root/.$(basename $f)
done

exit 0

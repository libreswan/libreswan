#!/bin/sh

set -xe ; exec < /dev/null

GATEWAY=@@GATEWAY@@
PREFIX=@@PREFIX@@
BENCHDIR=@@BENCHDIR@@
POOLDIR=@@POOLDIR@@
SOURCEDIR=@@SOURCEDIR@@
TESTINGDIR=@@TESTINGDIR@@

# update /etc/fstab with current /source and /testing

mkdir -p /source /testing
sed -e '/:/d' /etc/fstab > /tmp/fstab

cat <<EOF >> /tmp/fstab
${GATEWAY}:${SOURCEDIR}   /source         nfs     rw,noauto
${GATEWAY}:${TESTINGDIR}  /testing        nfs     rw,noauto
EOF

mv /tmp/fstab /etc/fstab
cat /etc/fstab

k=/pool/${PREFIX}netbsd-kernel
if test -r $k ; then
    cp -v $k /netbsd
fi

chsh -s /usr/pkg/bin/bash root

for f in /bench/testing/kvm/root/[a-z]* ; do
    cp -v ${f} /root/.$(basename $f)
done

cp -v /bench/testing/kvm/netbsd/auto_master /etc/
cp -v /bench/testing/kvm/netbsd/rc.local /etc/
cp -v /bench/testing/kvm/netbsd/rc.conf /etc/
cp -v /bench/testing/kvm/netbsd/sysctl.conf /etc/

exit 0

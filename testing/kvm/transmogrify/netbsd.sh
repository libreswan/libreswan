#!/bin/sh

set -xe ; exec < /dev/null

GATEWAY=@@GATEWAY@@
PREFIX=@@KVM_PREFIX@@
BENCHDIR=@@KVM_BENCHDIR@@
POOLDIR=@@KVM_POOLDIR@@
SOURCEDIR=@@KVM_SOURCEDIR@@
TESTINGDIR=@@KVM_TESTINGDIR@@

# update /etc/fstab with current /source and /testing

mkdir -p /source /testing
sed -e '/:/d' /etc/fstab > /tmp/fstab

cat <<EOF >> /tmp/fstab
${GATEWAY}:${SOURCEDIR}   /source         nfs     rw,noauto
${GATEWAY}:${TESTINGDIR}  /testing        nfs     rw,noauto
${GATEWAY}:${POOLDIR}     /pool           nfs     rw,noauto
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

cp -v /bench/testing/kvm/rc.d/rc.hostname                /etc/rc.hostname
cp -v /bench/testing/kvm/transmogrify/netbsd.rc.conf     /etc/rc.conf
cp -v /bench/testing/kvm/transmogrify/netbsd.auto_master /etc/auto_master
cp -v /bench/testing/kvm/transmogrify/netbsd.sysctl.conf /etc/sysctl.conf

exit 0

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

chsh -s /usr/local/bin/bash root
cp -v /bench/testing/libvirt/bash_profile /root/.bash_profile

cp -v /bench/testing/libvirt/freebsd/rc.conf /etc/

cp -v /bench/testing/libvirt/freebsd/auto_master /etc/

# supress motd
touch /root/.hushlogin

exit 0

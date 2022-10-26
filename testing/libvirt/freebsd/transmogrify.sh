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
sed -e '/source/d' -e '/testing/d' /etc/fstab > /tmp/fstab
cat <<EOF | tee -a /tmp/fstab
${GATEWAY}:${SOURCEDIR}   /source         nfs     rw
${GATEWAY}:${TESTINGDIR}  /testing        nfs     rw
EOF
mv /tmp/fstab /etc/fstab

# change ROOT's shell to BASH
#
# Test scripts assume an SH like shell; but FreeBSD defaults to CSH.

chsh -s /usr/local/bin/bash root
cp -v /bench/testing/libvirt/bash_profile /root/.bash_profile

# supress motd
touch /root/.hushlogin

cp -v /bench/testing/libvirt/freebsd/rc.conf /etc/rc.conf

exit 0

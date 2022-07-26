#!/bin/sh

set -ex

GATEWAY=@@GATEWAY@@
POOLDIR=@@POOLDIR@@
SOURCEDIR=@@SOURCEDIR@@
TESTINGDIR=@@TESTINGDIR@@

echo GATEWAY=${GATEWAY}
echo POOLDIR=${POOLDIR}
echo SOURCEDIR=${SOURCEDIR}
echo TESTINGDIR=${TESTINGDIR}

# update /etc/fstab with current /source and /testing
mkdir -p /pool /source /testing
sed -e '/source/d' -e '/testing/d' /etc/fstab > /tmp/fstab
cat <<EOF | tee -a /tmp/fstab
${GATEWAY}:${SOURCEDIR}   /source         nfs     rw
${GATEWAY}:${TESTINGDIR}  /testing        nfs     rw
EOF
mv /tmp/fstab /etc/fstab

# mount testing to get more files
# XXX: broken; should copy from /pool.
mount /testing

# change ROOT's shell to BASH
#
# Test scripts assume an SH like shell; but FreeBSD defaults to CSH.

# XXX: broken; should copy from /pool.
chsh -s /usr/local/bin/bash root
cp -v /testing/libvirt/bashrc /root/.bash_profile

# supress motd
touch /root/.hushlogin

# XXX: broken; should copy from /pool.
cp -v /testing/libvirt/freebsd/rc.conf /etc

exit 0

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

# change ROOT's shell to BASH
chsh -s /usr/local/bin/bash root

# supress motd
touch /root/.hushlogin

# mount testing to get more files
mount /testing
cp /testing/libvirt/freebsd/rc.conf /etc

exit 0

#!/bin/sh

set -xe ; exec < /dev/null

GATEWAY=@@GATEWAY@@
POOLDIR=@@POOLDIR@@
SOURCEDIR=@@SOURCEDIR@@
TESTINGDIR=@@TESTINGDIR@@
PREFIX=@@PREFIX@@

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
#
# Test scripts assume an SH like shell; but FreeBSD defaults to CSH.

chsh -s /usr/local/bin/bash root
cp -v /pool/${PREFIX}freebsd.bash_profile /root/.bash_profile

# suppress motd
touch /root/.hushlogin

cp -v /pool/${PREFIX}freebsd.rc.conf /etc/rc.conf

exit 0

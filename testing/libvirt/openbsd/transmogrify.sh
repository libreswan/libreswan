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
sed -i -e '/source/d' -e '/testing/d' /etc/fstab
cat <<EOF | tee -a /etc/fstab
${GATEWAY}:${SOURCEDIR}   /source   nfs  rw,tcp
${GATEWAY}:${TESTINGDIR}  /testing  nfs  rw,tcp
EOF

cp -v /pool/${PREFIX}openbsd.rc.local /etc/rc.local
chmod a+x /etc/rc.local

chsh -s /usr/local/bin/bash root
cp -v /pool/${PREFIX}openbsd.bash_profile /root/.bash_profile

exit 0

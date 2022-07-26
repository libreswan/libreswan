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
sed -i -e '/source/d' -e '/testing/d' /etc/fstab
cat <<EOF | tee -a /etc/fstab
${GATEWAY}:${SOURCEDIR}   /source   nfs  rw,tcp
${GATEWAY}:${TESTINGDIR}  /testing  nfs  rw,tcp
EOF

# mount testing to get more files
# XXX: broken; should copy from /pool.
mount /testing

# XXX: broken; should copy from /pool.
cp -v /testing/libvirt/openbsd/rc.local /etc/rc.local
chmod a+x /etc/rc.local

# XXX: broken; should copy from /pool.
chsh -s /usr/local/bin/bash root
cp -v /testing/libvirt/bashrc /root/.bash_profile

exit 0

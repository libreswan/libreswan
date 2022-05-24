#!/bin/sh

set -ex

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

mkdir -p /source /testing
sed -i -e '/source/d' -e '/testing/d' /etc/fstab
cat <<EOF | tee -a /etc/fstab
${GATEWAY}:${SOURCEDIR}   /source         nfs     rw
${GATEWAY}:${TESTINGDIR}  /testing        nfs     rw
EOF
echo
cat /etc/fstab
echo

k=/pool/${PREFIX}netbsd-kernel
if test -r $k ; then
    cp -v $k /netbsd
fi

mount /testing
cp -v /testing/libvirt/netbsd/rc.local /etc/

exit 0

#!/bin/sh

set -xe ; exec < /dev/null

# update /etc/fstab with current /source and /testing

GATEWAY=@@GATEWAY@@
PREFIX=@@PREFIX@@
BENCHDIR=@@BENCHDIR@@
POOLDIR=@@POOLDIR@@
SOURCEDIR=@@SOURCEDIR@@
TESTINGDIR=@@TESTINGDIR@@

:
: fstab
:

# strip out /pool and bench, then add in /source and /testing

mkdir -p /source /testing
sed -e '/:/d' /etc/fstab > /tmp/fstab

cat <<EOF >> /tmp/fstab
@@GATEWAY@@:@@SOURCEDIR@@   /source         nfs     rw
@@GATEWAY@@:@@TESTINGDIR@@  /testing        nfs     rw
EOF

mv /tmp/fstab /etc/fstab
cat /etc/fstab


:
: systemd
:

. /bench/testing/kvm/systemd/transmogrify-networkd.sh
. /bench/testing/kvm/systemd/transmogrify-hostnamer.sh

:
: bash
:

chsh -s /bin/bash root

for f in /bench/testing/kvm/root/[a-z]* ; do
    cp -v ${f} /root/.$(basename $f)
done

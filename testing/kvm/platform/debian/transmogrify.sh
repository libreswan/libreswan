#!/bin/sh

set -xe ; exec < /dev/null

# update /etc/fstab with current /source and /testing

export GATEWAY=@@GATEWAY@@
export PREFIX=@@PREFIX@@
export BENCHDIR=@@BENCHDIR@@
export POOLDIR=@@POOLDIR@@
export SOURCEDIR=@@SOURCEDIR@@
export TESTINGDIR=@@TESTINGDIR@@
export PLATFORM=@@PLATFORM@@

:
: fstab
:
: strip out all mounts first

mkdir -p /source /testing
sed -e '/9p/d' /etc/fstab > /tmp/fstab

cat <<EOF >> /tmp/fstab
pool  /pool  9p defaults,trans=virtio,version=9p2000.L,context=system_u:object_r:usr_t:s0,x-systemd.automount 0 0
source /source 9p defaults,trans=virtio,version=9p2000.L,context=system_u:object_r:usr_t:s0,x-systemd.automount 0 0
testing /testing 9p defaults,trans=virtio,version=9p2000.L,context=system_u:object_r:usr_t:s0,x-systemd.automount 0 0
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

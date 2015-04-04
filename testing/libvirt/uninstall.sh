#!/bin/sh

TESTING=$(dirname $(readlink -f $0))
TESTDIR=$(dirname $TESTING)
LIBRESWANSRCDIR=$(dirname $TESTDIR)

source ${LIBRESWANSRCDIR}/kvmsetup.sh

cd $TESTING

for netname in net/*; do
    net=$(basename $netname)
    sudo virsh net-destroy $net
    sudo virsh net-undefine $net
done

for hostfilename in swan${OSTYPE}base vm/*; do
    hostname=$(basename ${hostfilename})
    sudo virsh destroy $hostname
done

for hostfilename in swan${OSTYPE}base vm/*; do
    hostname=$(basename ${hostfilename})
    sudo virsh undefine $hostname --remove-all-storage
done

for f in img qcow2 ; do
    rm -f ${POOLSPACE}/swan"${OSTYPE}"base.$f
done

sudo virsh pool-destroy $(basename $POOLSPACE)
sudo virsh pool-undefine $(basename $POOLSPACE)

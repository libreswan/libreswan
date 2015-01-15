#!/bin/sh

TESTING=$(readlink -f $0 | sed "s/libvirt.*$/libvirt/")
TESTDIR=$(readlink -f $0 | sed "s/libvirt.*$//")
LIBRESWANSRCDIR=$(readlink -f $0 | sed "s/libreswan.*$/libreswan/")

source ${LIBRESWANSRCDIR}/kvmsetup.sh

cd $TESTING

for hostfilename in vm/*; do
    hostname=$(basename ${hostfilename})
    sudo virsh destroy $hostname
done

for hostfilename in vm/*; do
    hostname=$(basename ${hostfilename})
    sudo virsh undefine $hostname --remove-all-storage
done

for f in img qcow2 ; do
    rm -f ${POOLSPACE}/swan"${OSTYPE}"base.$f
done

sudo virsh pool-destroy $(basename $POOLSPACE)
sudo virsh pool-undefine $(basename $POOLSPACE)

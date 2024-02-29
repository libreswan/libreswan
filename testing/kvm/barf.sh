#!/bin/sh

sudo dnf debuginfo-install -y libvirt-daemon-driver-qemu libvirt-daemon-driver-storage-core libvirt-daemon-driver-network

for b in qemud storaged networkd ; do
    pid=$(pgrep virt${b})
    o=/tmp/virt.$b.stack
    banner $b | tee $o
    sudo gstack $pid | tee -a $o
done

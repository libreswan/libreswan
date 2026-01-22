#!/bin/sh

set -xe ; exec < /dev/null

:
: systemd-networkd
:

systemctl enable systemd-networkd.service
systemctl enable systemd-networkd-wait-online.service

# Drop hostname, instead rely either on the kernel cmdline and
# systemd.hostname=... or zzz.eth0.network which defaults to the local
# platform.

rm -f /etc/hostname
rm -f /etc/systemd/network/*
cp -v /bench/testing/kvm/systemd/network/*.network /etc/systemd/network/
sed -i -e "s/@@PLATFORM@@/${PLATFORM}/" /etc/systemd/network/*.network

# test specific configs; bound using ethernet addresses

if test -x /usr/sbin/restorecon ; then
    restorecon -R /etc/systemd/network
fi

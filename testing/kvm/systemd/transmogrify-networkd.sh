#!/bin/sh

set -xe ; exec < /dev/null

:
: Switch from NetworkManager to systemd-networkd+systemd-resolved
:

# Drop hostname, instead rely either on the kernel cmdline and
# systemd.hostname=... or zzz.eth0.network which defaults to the local
# platform.

rm -f /etc/hostname
rm -f /etc/systemd/network/*
cp -v /bench/testing/kvm/systemd/network/*.network /etc/systemd/network/
sed -i -e "s/@@DOMAIN_PLATFORM@@/${PLATFORM}/" /etc/systemd/network/*.network

# Debian, for instance, doesn't have NetworkManager
if systemctl status NetworkManager > /dev/null ; then
    systemctl disable NetworkManager
fi

systemctl enable systemd-networkd.service
systemctl enable systemd-networkd-wait-online.service

if test -x /usr/sbin/restorecon ; then
    restorecon -R /etc/systemd/network
fi

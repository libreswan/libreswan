#!/bin/sh

set -xe ; exec < /dev/null

:
: systemd-networkd
:

systemctl enable systemd-networkd.service
systemctl enable systemd-networkd-wait-online.service

cp -v /bench/testing/kvm/systemd/network/* /etc/systemd/network/
test -x /usr/sbin/restorecon && restorecon -R /etc/systemd/network

# Provide a default network configuration for build domain

# Since systemd-networkd matches .network files in lexographical
# order, this zzz.*.network file is only matched when all else fails.

cat > /etc/systemd/network/zzz.eth0.network << EOF
[Match]
Name=eth0
Host=${PLATFORM}
[Network]
Description=fallback for when no other interface matches
DHCP=yes
EOF

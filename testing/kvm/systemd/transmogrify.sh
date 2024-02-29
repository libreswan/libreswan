#!/bin/sh

set -xe ; exec < /dev/null

 . /etc/os-release

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
Host=${ID}
[Network]
Description=fallback for when no other interface matches
DHCP=yes
EOF


:
: hostnamer
:

# hostnamer runs whenever /etc/hostname is empty; it detects east,
# west, et.al., but for build domains lets the above kick in
# rm -f /etc/hostname # hostnamectl set-hostname ""

cp -v /bench/testing/kvm/systemd/hostnamer.service /etc/systemd/system
cp -v /bench/testing/kvm/systemd/hostnamer.sh /usr/local/sbin/hostnamer.sh
chmod a+x /usr/local/sbin/hostnamer.sh
test -x /usr/sbin/restorecon && restorecon -R /etc/systemd/system
systemctl enable hostnamer.service

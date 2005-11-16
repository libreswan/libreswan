#!/bin/sh
TZ=GMT export TZ
TERM=dump export TERM

dd if=/etc/inetd.64k bs=255 count=1 of=/proc/net/ipsec/birth/ipv4
cat /proc/net/ipsec/birth/ipv4; echo

dd if=/etc/inetd.64k skip=1 bs=255 count=1 of=/proc/net/ipsec/birth/ipv6
cat /proc/net/ipsec/birth/ipv6; echo

dd if=/etc/inetd.64k skip=2 bs=255 count=1 of=/proc/net/ipsec/birth/ipv4
cat /proc/net/ipsec/birth/ipv4; echo

dd if=/etc/inetd.64k bs=255 count=2 of=/proc/net/ipsec/birth/ipv6
cat /proc/net/ipsec/birth/ipv6; echo










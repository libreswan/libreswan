#!/bin/sh
../../guestbin/ping-once.sh --up 192.1.2.23
ipsec auto --up road-east-x509-ipv4
../../guestbin/ping-once.sh --up -I 192.0.2.100 192.1.2.23
ipsec status
sleep 60
sleep 60
../../guestbin/ping-once.sh --up -I 192.0.2.100 192.1.2.23
grep -E 'EVENT_.*_EXPIRE|EVENT_.*_REPLACE' OUTPUT/road.pluto.log | grep -e '#[0-9]' | sed -e 's/@0x[0-9a-f]*/@0xXXX/'
ipsec status
echo done

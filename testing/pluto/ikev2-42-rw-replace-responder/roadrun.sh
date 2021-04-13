#!/bin/sh
../../guestbin/ping-once.sh --up 192.1.2.23
ipsec auto --up road-east-x509-ipv4
../../guestbin/ping-once.sh --up -I 192.0.2.100 192.1.2.23
ipsec status
sleep 60
sleep 60
../../guestbin/ping-once.sh --up -I 192.0.2.100 192.1.2.23
grep -E  'EVENT_SA_EXPIRE|EVENT_SA_REPLACE' OUTPUT/road.pluto.log | grep -e '#[0-9]' | grep -v pe@
ipsec status
echo done

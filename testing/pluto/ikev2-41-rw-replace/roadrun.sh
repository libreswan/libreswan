#!/bin/sh
../../guestbin/ping-once.sh --up 192.1.2.23
ipsec auto --up road-east-x509-ipv4
../../guestbin/ping-once.sh --up -I 192.0.2.100 192.1.2.23
ipsec status
sleep 60
sleep 60
../../guestbin/ping-once.sh --up -I 192.0.2.100 192.1.2.23
grep -E  'EVENT_SA_EXPIRE|EVENT_SA_REPLACE' OUTPUT/road.pluto.log | grep '#' | sed -e 's/ timeout in [1-9][^ ]* / timeout in N.N /'
: "re-authenticateded. The state number should 3 and 2"
ipsec status
echo done

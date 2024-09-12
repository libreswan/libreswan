#!/bin/sh
../../guestbin/ping-once.sh --up 192.1.2.23
ipsec auto --up road-east-x509-ipv4
../../guestbin/ping-once.sh --up -I 192.0.2.100 192.1.2.23
ipsec status
../../guestbin/wait-for.sh --timeout 120 --match '^".*#3: initiator rekeyed IKE SA #1' -- cat /tmp/pluto.log
../../guestbin/wait-for-pluto.sh '^".*#1: deleting IKE SA'
../../guestbin/ping-once.sh --up -I 192.0.2.100 192.1.2.23
grep -E  'EVENT_v2_EXPIRE|EVENT_v2_REPLACE' OUTPUT/road.pluto.log | grep '#' | sed -e 's/ timeout in [1-9][^ ]* / timeout in N.N /' -e 's/@0x[0-9a-f]*/@0xXXX/' -e 's/ (.*//'
: "re-authenticateded. The state number should 3 and 2"
ipsec status
echo done

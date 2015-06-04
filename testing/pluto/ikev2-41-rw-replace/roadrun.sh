#!/bin/sh
ping -q -n -c 2 192.1.2.23
ipsec auto --up road-east-x509-ipv4
ping -q -n -c 4 -I 192.0.2.100 192.1.2.23
ipsec status
sleep 60
sleep 60
ping -q -n -c 4 -I 192.0.2.100 192.1.2.23
grep -E  'EVENT_SA_EXPIRE|EVENT_SA_REPLACE' OUTPUT/road.pluto.log  | head -9
echo "re-authenticateded. The state number should 3 and 4"
ipsec status
echo done

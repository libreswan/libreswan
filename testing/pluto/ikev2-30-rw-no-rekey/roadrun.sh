#!/bin/sh
ping -q -n -c 2 192.1.2.23
ipsec auto --up road-east-x509-ipv4
echo "sleep 110 seconds"
sleep 30
sleep 30
sleep 30
sleep 20
# tunnel should be gone
ipsec whack --trafficstatus
echo done

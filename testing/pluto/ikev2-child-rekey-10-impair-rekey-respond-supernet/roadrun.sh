#!/bin/sh
../../guestbin/ping-once.sh --up 192.1.2.23
ipsec auto --up road-east-x509-ipv4
../../guestbin/ping-once.sh --up -I 192.0.2.100 192.1.2.23
ipsec whack --trafficstatus
ipsec whack --rekey-child --name road-east-x509-ipv4 --async
echo "sleep 40 seconds"
sleep 40
# should be #2 not #3
ipsec trafficstatus
echo done

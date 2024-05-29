#!/bin/sh
../../guestbin/route.sh -4
ipsec auto --up road-east-x509-ipv4
../../guestbin/ping-once.sh --up 192.0.2.254
ipsec whack --trafficstatus
../../guestbin/route.sh -4
echo done

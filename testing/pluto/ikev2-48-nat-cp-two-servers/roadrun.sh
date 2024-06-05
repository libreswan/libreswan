#!/bin/sh
../../guestbin/ip.sh -4 route
ipsec auto --up road-east-x509-ipv4
../../guestbin/ping-once.sh --up 192.0.2.254
ipsec whack --trafficstatus
../../guestbin/ip.sh -4 route
# now bring up second connection to west with CP request as well
ipsec auto --up road-west-x509-ipv4
../../guestbin/ping-once.sh --up 192.0.1.254
../../guestbin/ip.sh -4 route
echo done

#!/bin/sh
ip -4 route
ipsec auto --up road-east-x509-ipv4
ping -q -n -c 4 192.0.2.254
ipsec whack --trafficstatus
ip -4 route
echo done

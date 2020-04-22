#!/bin/sh
ping -q -n -c 2 192.1.2.23
ipsec auto --up road-east-x509-ipv4
ping -q -n -c 4 -I 192.0.2.100 192.1.2.23
ipsec whack --trafficstatus
ipsec whack --impair rekey-initiate-subnet
ipsec whack --rekey-ipsec --name road-east-x509-ipv4
echo "sleep 40 seconds"
sleep 40
ping -q -n -c 4 -I 192.0.2.100 192.1.2.23
echo done

#!/bin/sh
ping -q -n -c 2 192.1.2.23
ipsec auto --up road-east-x509-ipv4
ping -q -n -c 4 -I 192.0.2.100 192.1.2.23
ipsec whack --trafficstatus
# Let R_U_THERE packets flow
echo "Waiting 15 seconds..."
sleep 15
echo "Setting up block via iptables"
iptables -I INPUT -s 192.1.2.23/32 -d 0/0 -j DROP
iptables -I OUTPUT -d 192.1.2.23/32 -s 0/0 -j DROP
echo "sleep 110 seconds"
sleep 30
sleep 30
sleep 30
sleep 20
# tunnel should be gone
ipsec whack --trafficstatus
echo done

#!/bin/sh
ping -q -n -c 2 192.1.2.23
ipsec auto --up road-east-x509-ipv4
ping -q -n -c 4 -I 192.0.2.100 192.1.2.23
ipsec whack --trafficstatus
# Let R_U_THERE packets flow
echo "Waiting 15 seconds..."
sleep 15
# "Setting up block via iptables"
iptables -I INPUT -s 192.1.2.23/32 -d 0/0 -j DROP
iptables -I OUTPUT -d 192.1.2.23/32 -s 0/0 -j DROP
echo "sleep 110 seconds"
sleep 60
sleep 50
echo "road should be retrying again. Remove the block"
iptables -D INPUT -s 192.1.2.23/32 -d 0/0 -j DROP
iptables -D OUTPUT -d 192.1.2.23/32 -s 0/0 -j DROP
../../pluto/bin/ipsec-look.sh
echo "sleep 110 seconds"
sleep 60
ping -q -n -c 4 -I 192.0.2.100 192.1.2.23
echo done

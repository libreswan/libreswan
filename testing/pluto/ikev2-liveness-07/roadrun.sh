#!/bin/sh
ipsec auto --up road-east-x509-ipv4
ping -n -c4 -I 192.0.2.100 192.1.2.23
# show the tunnel!
echo "Tunnel should be up"
ipsec eroute
# Let R_U_THERE packets flow
echo "Waiting 15 seconds..."
sleep 15
echo "Setting up block via iptables"
iptables -I INPUT -s 192.1.2.23/32 -d 0/0 -j DROP
iptables -I OUTPUT -d 192.1.2.23/32 -s 0/0 -j DROP
sleep 10
sleep 10
sleep 10
# DPD should have triggered now
echo "Tunnel should be down (%trap/%hold)"
ipsec eroute
iptables -D INPUT -s 192.1.2.23/32 -d 0/0 -j DROP
iptables -D OUTPUT -d 192.1.2.23/32 -s 0/0 -j DROP
# as long as retransmits might take 20,40,40 seconds
sleep 60
# Tunnel should be back up now even without triggering traffic
echo "Tunnel should be up even without trigger traffic"
ipsec eroute
ping -q -n -c 4 -I 192.0.2.100 192.1.2.23
echo done 

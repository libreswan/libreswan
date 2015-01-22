#!/bin/sh
ipsec auto --up westnet-eastnet-ikev2
# use the tunnel
ping -q -n -c 8 -I 192.0.1.254 192.0.2.254
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
echo "Tunnel should be down with %trap or %hold preventing packet leaks"
ipsec eroute
# Remove the Blockage
echo "Removing block"
iptables -D INPUT -s 192.1.2.23/32 -d 0/0 -j DROP
iptables -D OUTPUT -d 192.1.2.23/32 -s 0/0 -j DROP
# Sleep 90
sleep 60
sleep 30
# Tunnel should be back up now even without triggering traffic
echo "Tunnel should be up even without trigger traffic"
ipsec eroute
ping -q -n -c 8 -I 192.0.1.254 192.0.2.254
echo done

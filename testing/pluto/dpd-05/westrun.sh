#!/bin/sh
# we can transmit in the clear
ping -q -c 4 -n -I 192.1.2.45 192.1.2.23
# bring up the tunnel
ipsec auto --up west-east
# use the tunnel
ping -q -c 4 -n -I 192.1.2.45 192.1.2.23
# show the tunnel!
echo "Tunnel should be up"
ipsec whack --trafficstatus
# Let R_U_THERE packets flow
echo "Waiting 15 seconds..."
sleep 15
echo "Setting up block via iptables"
iptables -I INPUT -s 192.1.2.23/32 -d 0/0 -j DROP
iptables -I OUTPUT -d 192.1.2.23/32 -s 0/0 -j DROP
: ==== cut ====
sleep 10
ipsec whack --trafficstatus
sleep 10
ipsec whack --trafficstatus
sleep 10
: ==== tuc ====
# DPD should have triggered now
echo "Tunnel should be down"
ipsec whack --trafficstatus
# Remove the Blockage
echo "Removing block"
iptables -D INPUT -s 192.1.2.23/32 -d 0/0 -j DROP
iptables -D OUTPUT -d 192.1.2.23/32 -s 0/0 -j DROP
sleep 10
ping -q -c 4 -n -I 192.1.2.45 192.1.2.23
# Tunnel should be back up now
echo "Tunnel should be up"
ipsec whack --trafficstatus
echo done

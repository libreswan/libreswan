#!/bin/sh
# we can transmit in the clear
ping -q -c 8 -n 192.1.2.23
# bring up the tunnel
ipsec auto --up west-east
# use the tunnel
ping -q -c 8 -n 192.1.2.23
# show the tunnel!
echo "Tunnel should be up"
ipsec look
# Let R_U_THERE packets flow
echo "Waiting 15 seconds..."
sleep 15
echo "Setting up block via iptables"
iptables -I INPUT -s 192.1.2.23/32 -d 0/0 -j DROP
iptables -I OUTPUT -d 192.1.2.23/32 -s 0/0 -j DROP
: ==== cut ====
sleep 10
ipsec look
sleep 10
ipsec look
sleep 10
: ==== tuc ====
# DPD should have triggered now
echo "Tunnel should be down (%trap/%hold)"
ipsec look
# Remove the Blockage
echo "Removing block"
iptables -D INPUT -s 192.1.2.23/32 -d 0/0 -j DROP
iptables -D OUTPUT -d 192.1.2.23/32 -s 0/0 -j DROP
sleep 10
# Tunnel should be back up now even without triggering traffic
echo "Tunnel should be up even without trigger traffic"
ipsec look
ping -q -c 8 -n 192.1.2.23
echo end

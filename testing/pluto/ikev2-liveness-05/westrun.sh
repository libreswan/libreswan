#!/bin/sh
ipsec auto --up westnet-eastnet-ikev2
ping -q -n -c 4 -I 192.0.1.254 192.0.2.254
# Tunnel should be up
ipsec whack --trafficstatus
# Let R_U_THERE packets flow
sleep 15
# Setting up block via iptables
iptables -I INPUT -s 192.1.2.23/32 -d 0/0 -j DROP
iptables -I OUTPUT -d 192.1.2.23/32 -s 0/0 -j DROP
sleep 30
# DPD should have triggered now
# Tunnel should be down with %trap or %hold preventing packet leaks
# But shuntstatus only shows bare shunts, not connection shunts :(
ipsec whack --trafficstatus
ipsec whack --shuntstatus
# no packets should be caught in firewall and no icmp replies should happen
ping -w 2 -q -n -c 3 -I 192.0.1.254 192.0.2.254
# Remove the Blockage
iptables -D INPUT -s 192.1.2.23/32 -d 0/0 -j DROP
iptables -D OUTPUT -d 192.1.2.23/32 -s 0/0 -j DROP
# Sleep 90
sleep 60
sleep 30
# Tunnel should be back up now even without triggering traffic
ipsec whack --trafficstatus
ipsec whack --shuntstatus
# ping should reply
ping -q -n -c 4 -I 192.0.1.254 192.0.2.254
echo done

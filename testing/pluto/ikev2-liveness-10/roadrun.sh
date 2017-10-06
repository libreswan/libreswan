#!/bin/sh
ipsec auto --up road-east-x509-ipv4
ping -n -c4 -I 192.0.2.100 192.1.2.23
# Tunnel should be up
ipsec whack --trafficstatus
# Let R_U_THERE packets flow
sleep 15
# Setting up block via iptables
iptables -I INPUT -s 192.1.2.23/32 -d 0/0 -j DROP
iptables -I OUTPUT -d 192.1.2.23/32 -s 0/0 -j DROP
sleep 30
# Tunnel should be down (%trap/%hold)
ipsec whack --trafficstatus
iptables -D INPUT -s 192.1.2.23/32 -d 0/0 -j DROP
iptables -D OUTPUT -d 192.1.2.23/32 -s 0/0 -j DROP
sleep 30
# Tunnel should be back up now even without triggering traffic
ipsec whack --trafficstatus
ping -q -n -c 4 -I 192.0.2.100 192.1.2.23
echo done

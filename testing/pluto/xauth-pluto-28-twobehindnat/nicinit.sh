#!/bin/sh
iptables -t nat -F
iptables -F
# NAT
# eth0: 192.1.2.254 - external
# eth1: 192.1.3.254 - internal
# iptables -t nat -A POSTROUTING --source 192.1.3.0/24 --destination 0.0.0.0/0 -j SNAT --to-source 192.1.2.254
iptables -t nat -A POSTROUTING -o eth0 -j MASQUERADE --proto TCP --source 192.1.3.0/24 --to-port 40000-60000
iptables -t nat -A POSTROUTING -o eth0 -j MASQUERADE --proto UDP --source 192.1.3.0/24 --to-port 40000-60000
# make sure that we never acidentially let ESP through.
iptables -I FORWARD 1 --proto 50 -j DROP
#iptables -I FORWARD 2 --destination 192.0.2.0/24 -j DROP
#iptables -I FORWARD 3 --source 192.0.2.0/24 -j DROP
# route
#iptables -I INPUT 1 --destination 192.0.2.0/24 -j DROP
# Display the table, so we know it is correct.
iptables -t nat -L -n
iptables -L -n
echo done.
: ==== end ====

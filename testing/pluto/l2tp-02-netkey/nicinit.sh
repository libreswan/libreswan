#!/bin/sh
iptables -t nat -F
iptables -F
# NAT
iptables -t nat -A POSTROUTING --source 192.1.3.0/24 --destination 0.0.0.0/0 -j SNAT --to-source 192.1.2.254
# make sure that we never acidentially let ESP or L2TP through.
iptables -N LOGDROP
iptables -A LOGDROP -j LOG
iptables -A LOGDROP -j DROP
iptables -I FORWARD 1 --proto 50 -j LOGDROP
iptables -I FORWARD 2 --proto udp --dport 1701 -j LOGDROP
# Display the table, so we know it is correct.
iptables -t nat -L -n
iptables -L -n
echo done

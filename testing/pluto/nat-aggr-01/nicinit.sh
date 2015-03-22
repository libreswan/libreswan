#!/bin/sh
iptables -t nat -F
iptables -F
# NAT North's IP to ours
iptables -t nat -A POSTROUTING --source 192.1.3.0/24 --destination 0.0.0.0/0 -j SNAT --to-source 192.1.2.254
# make sure that we never acidentially let ESP through.
iptables -I OUTPUT 1 --proto 50 -j DROP
# Display the table, so we know it is correct.
iptables -t nat -L
iptables -L
echo done.

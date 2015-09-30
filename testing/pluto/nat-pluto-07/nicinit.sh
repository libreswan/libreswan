#!/bin/sh

ifconfig eth0:1 inet 192.1.2.111 netmask 255.255.255.0

# NAT North's IP to ours
iptables -t nat -F POSTROUTING
iptables -t nat -A POSTROUTING --source 192.1.3.0/24 --destination 0.0.0.0/0 -o eth0+ -p udp -m udp --dport 500  -j SNAT --to-source 192.1.2.254:11000-12000
iptables -t nat -A POSTROUTING --source 192.1.3.0/24 --destination 0.0.0.0/0 -o eth0+ -p udp -m udp --dport 4500 -j SNAT --to-source 192.1.2.111:14000-16000

iptables -A OUTPUT -d 192.0.2.0/24 -j DROP

# Display the table, so we know it is correct.
iptables -t nat -L -v

echo done.

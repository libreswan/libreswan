#!/bin/sh

# NAT North's IP to ours
iptables -t nat -A POSTROUTING --source 192.1.3.0/24 --destination 0.0.0.0/0 -j SNAT --to-source 192.1.2.254

# Display the table, so we know it is correct.
iptables -t nat -L

echo done.

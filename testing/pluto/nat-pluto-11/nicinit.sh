#!/bin/sh
# setup port/protocol forward to east
iptables -t nat -I PREROUTING -p udp -d 192.1.3.254 --dport 500 -j DNAT --to-destination 192.1.2.23
iptables -t nat -I PREROUTING -p esp -d 192.1.3.254 -j DNAT --to-destination 192.1.2.23
# Display the table, so we know it is correct.
iptables -t nat -L
echo "initdone"
: ==== end ====

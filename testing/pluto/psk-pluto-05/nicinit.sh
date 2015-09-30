#!/bin/sh
# Display the table, so we know it is correct.
iptables -t nat -L
echo "initdone"

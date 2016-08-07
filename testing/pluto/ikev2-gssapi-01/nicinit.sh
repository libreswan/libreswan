#!/bin/sh
iptables -t nat -F
# Display the table, so we know it is correct.
iptables -t nat -L -n
iptables -L -n
# become KDC
ipactl start
sleep 5
echo done.

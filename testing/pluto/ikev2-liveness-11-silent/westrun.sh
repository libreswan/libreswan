#!/bin/sh
# we can transmit in the clear
ping -q -c 8 -n 192.1.2.23
# bring up the tunnel
ipsec auto --up west-east
# use the tunnel
ping -q -c 8 -n 192.1.2.23
# show the tunnel!
echo "Tunnel should be up"
ipsec whack --trafficstatus
# Wait more then 15 seconds while ensuring there is traffic
sleep 1
ping -q -c 1 -n 192.1.2.23 >/dev/null
sleep 1
ping -q -c 1 -n 192.1.2.23 >/dev/null
sleep 1
ping -q -c 1 -n 192.1.2.23 >/dev/null
sleep 1
ping -q -c 1 -n 192.1.2.23 >/dev/null
sleep 1
ping -q -c 1 -n 192.1.2.23 >/dev/null
sleep 1
ping -q -c 1 -n 192.1.2.23 >/dev/null
sleep 1
ping -q -c 1 -n 192.1.2.23 >/dev/null
sleep 1
ping -q -c 1 -n 192.1.2.23 >/dev/null
sleep 1
ping -q -c 1 -n 192.1.2.23 >/dev/null
sleep 1
ping -q -c 1 -n 192.1.2.23 >/dev/null
# force a rekey
ipsec auto --up west-east
sleep 1
ping -q -c 1 -n 192.1.2.23 >/dev/null
sleep 1
ping -q -c 1 -n 192.1.2.23 >/dev/null
sleep 1
ping -q -c 1 -n 192.1.2.23 >/dev/null
sleep 1
ping -q -c 1 -n 192.1.2.23 >/dev/null
sleep 1
ping -q -c 1 -n 192.1.2.23 >/dev/null
sleep 1
ping -q -c 1 -n 192.1.2.23 >/dev/null
sleep 1
ping -q -c 1 -n 192.1.2.23 >/dev/null
sleep 1
ping -q -c 1 -n 192.1.2.23 >/dev/null
echo done

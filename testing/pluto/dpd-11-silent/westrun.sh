#!/bin/sh
# we can transmit in the clear
../../guestbin/ping-once.sh --up 192.1.2.23
# bring up the tunnel
ipsec auto --up west-east
# use the tunnel
../../guestbin/ping-once.sh --up 192.1.2.23
# show the tunnel!
echo "Tunnel should be up"
ipsec whack --trafficstatus
# Wait more then 15 seconds while ensuring there is traffic
sleep 1
ping -n -q -c 1 192.1.2.23 >/dev/null
sleep 1
ping -n -q -c 1 192.1.2.23 >/dev/null
sleep 1
ping -n -q -c 1 192.1.2.23 >/dev/null
sleep 1
ping -n -q -c 1 192.1.2.23 >/dev/null
sleep 1
ping -n -q -c 1 192.1.2.23 >/dev/null
sleep 1
ping -n -q -c 1 192.1.2.23 >/dev/null
sleep 1
ping -n -q -c 1 192.1.2.23 >/dev/null
sleep 1
ping -n -q -c 1 192.1.2.23 >/dev/null
sleep 1
ping -n -q -c 1 192.1.2.23 >/dev/null
sleep 1
ping -n -q -c 1 192.1.2.23 >/dev/null
# force a rekey
ipsec auto --up west-east
sleep 1
ping -n -q -c 1 192.1.2.23 >/dev/null
sleep 1
ping -n -q -c 1 192.1.2.23 >/dev/null
sleep 1
ping -n -q -c 1 192.1.2.23 >/dev/null
sleep 1
ping -n -q -c 1 192.1.2.23 >/dev/null
sleep 1
ping -n -q -c 1 192.1.2.23 >/dev/null
sleep 1
ping -n -q -c 1 192.1.2.23 >/dev/null
sleep 1
ping -n -q -c 1 192.1.2.23 >/dev/null
sleep 1
ping -n -q -c 1 192.1.2.23 >/dev/null
echo done

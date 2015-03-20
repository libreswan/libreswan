#!/bin/sh

# we can transmit in the clear
ping -q -c 4 -n 192.1.2.23

# bring up the tunnel
ipsec auto --up west-east

# use the tunnel
ping -q -c 4 -n 192.1.2.23

# show the tunnel!
echo "Tunnel should be up"
ipsec eroute

# Let R_U_THERE packets flow
echo "Waiting 15 seconds..."
sleep 15

echo "Crashing east"
ssh 192.1.2.23 killall -9 pluto

echo "Waiting 120s to see if we mistakenly stop retrying"
sleep 120

echo end

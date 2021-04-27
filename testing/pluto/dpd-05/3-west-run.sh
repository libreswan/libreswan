#!/bin/sh
# we can transmit in the clear
../../guestbin/ping-once.sh --up -I 192.1.2.45 192.1.2.23
# bring up the tunnel
ipsec auto --up west-east
# use the tunnel
../../guestbin/ping-once.sh --up -I 192.1.2.45 192.1.2.23
# show the tunnel!
ipsec whack --trafficstatus
# Let R_U_THERE packets flow
sleep 15
# Setting up block via iptables
iptables -I INPUT -s 192.1.2.23/32 -d 0/0 -j DROP
iptables -I OUTPUT -d 192.1.2.23/32 -s 0/0 -j DROP
# wait for DPD to trigger
../../guestbin/wait-for.sh --no-match ':' -- ipsec whack --trafficstatus
# Remove the Blockage
iptables -D INPUT -s 192.1.2.23/32 -d 0/0 -j DROP
iptables -D OUTPUT -d 192.1.2.23/32 -s 0/0 -j DROP
# wait for tunnel to come back up
../../guestbin/wait-for.sh --match 'west-east' -- ipsec whack --trafficstatus
../../guestbin/ping-once.sh --up -I 192.1.2.45 192.1.2.23
ipsec whack --trafficstatus
echo done

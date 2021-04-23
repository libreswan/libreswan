# we can transmit in the clear
../../guestbin/ping-once.sh --up -I 192.1.2.45 192.1.2.23
# bring up the tunnel
ipsec auto --up west-east
ipsec auto --up west-eastnet
ipsec auto --up westnet-east
# use the tunnel
../../guestbin/ping-once.sh --up -I 192.1.2.45 192.1.2.23
# show the tunnel
ipsec whack --trafficstatus
# Let R_U_THERE packets flow
sleep 10
sleep 10
# Create the block; wait for DPD to trigger
iptables -I INPUT -s 192.1.2.23/32 -d 0/0 -j DROP
../../guestbin/wait-for.sh --no-match ':' -- ipsec whack --trafficstatus
# remove the block
iptables -D INPUT -s 192.1.2.23/32 -d 0/0 -j DROP
# wait for west-east
../../guestbin/wait-for.sh --match '"west-east"' -- ipsec whack --trafficstatus
../../guestbin/ping-once.sh --up -I 192.1.2.45 192.1.2.23
# trigger westnet-east
../../guestbin/ping-once.sh --down -I 192.0.1.254 192.1.2.23
../../guestbin/wait-for.sh --match '"westnet-east"' -- ipsec whack --trafficstatus
../../guestbin/ping-once.sh --up -I 192.0.1.254 192.1.2.23
../../guestbin/ping-once.sh --up -I 192.0.1.254 192.1.2.23
# trigger west-eastnet
../../guestbin/ping-once.sh --down -I 192.1.2.45 192.0.2.254
../../guestbin/wait-for.sh --match '"west-eastnet"' -- ipsec whack --trafficstatus
../../guestbin/ping-once.sh --up -I 192.1.2.45 192.0.2.254
../../guestbin/ping-once.sh --up -I 192.1.2.45 192.0.2.254
../../guestbin/ping-once.sh --up -I 192.1.2.45 192.0.2.254
# Tunnels should be back up now
ipsec whack --trafficstatus
echo done

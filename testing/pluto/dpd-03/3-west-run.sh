# we can transmit in the clear
../../guestbin/ping-once.sh --up -I 192.1.2.45 192.1.2.23
# bring up the tunnel
ipsec auto --up west-east
# use the tunnel; show the tunnel
../../guestbin/ping-once.sh --up -I 192.1.2.45 192.1.2.23
ipsec whack --trafficstatus
# Let R_U_THERE packets flow
sleep 10
: ==== cut ====
ipsec whack --trafficstatus
: ==== tuc ====
sleep 10
# Create the block; wait for DPD to trigger
iptables -I INPUT -s 192.1.2.23/32 -d 0/0 -j DROP
../../guestbin/wait-for.sh --no-match '#2:' -- ipsec whack --trafficstatus
: ==== cut ====
ipsec whack --listevents
ipsec whack --trafficstatus
: ==== tuc ====
# remove the block; wait for tunnel
iptables -D INPUT -s 192.1.2.23/32 -d 0/0 -j DROP
../../guestbin/wait-for.sh --match 'west-east' -- ipsec whack --trafficstatus
# Tunnel should be back up now
../../guestbin/ping-once.sh --up -I 192.1.2.45 192.1.2.23
ipsec whack --trafficstatus
echo done

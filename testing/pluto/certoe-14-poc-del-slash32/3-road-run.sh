# wait on OE retransmits and rekeying
ipsec whack --trafficstatus
../../guestbin/ping-once.sh --forget -I 192.1.3.209 192.1.2.23
../../guestbin/wait-for.sh --match private-or-clear -- ipsec whack --trafficstatus

# should show established tunnel and no bare shunts and should succeed through tunnel
../../guestbin/ping-once.sh --up -I 192.1.3.209 192.1.2.23
ipsec whack --trafficstatus
ipsec whack --shuntstatus

echo "waiting on east to send delete for this IPsec SA"

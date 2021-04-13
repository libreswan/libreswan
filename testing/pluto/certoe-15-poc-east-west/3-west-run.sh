# wait on OE retransmits and rekeying
../../guestbin/ping-once.sh --forget -I 192.1.2.45 192.1.2.23
../../guestbin/wait-for.sh --match private -- ipsec whack --trafficstatus
# should show established tunnel and no bare shunts
../../guestbin/ping-once.sh --up -I 192.1.2.45 192.1.2.23
ipsec whack --trafficstatus
ipsec whack --shuntstatus
echo "waiting on east to send delete for this IPsec SA"

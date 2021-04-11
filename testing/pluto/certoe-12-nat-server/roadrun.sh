# one packet, which gets eaten by XFRM, so east does not initiate
../../guestbin/ping-once.sh --down -I 192.1.3.209 192.1.3.130
# wait on OE IKE negotiation
# ping should succeed through tunnel
../../guestbin/ping-once.sh --up -I 192.1.3.209 192.1.3.130
sleep 1
# should show established tunnel and no bare shunts
ipsec whack --trafficstatus
ipsec whack --shuntstatus
echo done

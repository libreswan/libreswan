ping -n -c 5 -I 192.1.2.45 192.1.2.23
# wait on OE retransmits and rekeying
sleep 5
# should show established tunnel and no bare shunts
ipsec whack --trafficstatus
ipsec whack --shuntstatus
# ping should succeed through tunnel
ping -n -c 2 -I 192.1.2.45 192.1.2.23
ipsec whack --trafficstatus
echo "waiting on east to send delete for this IPsec SA"

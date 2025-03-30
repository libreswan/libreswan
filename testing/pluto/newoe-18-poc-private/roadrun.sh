../../guestbin/ping-once.sh --down -I 192.1.3.209 192.1.2.23
# wait on OE retransmits and rekeying
sleep 5
# should show established tunnel and no bare shunts
ipsec whack --trafficstatus
ipsec whack --shuntstatus
ipsec _kernel state
ipsec _kernel policy
killall ip > /dev/null 2> /dev/null
cp /tmp/xfrm-monitor.out OUTPUT/road.xfrm-monitor.txt
# ping should succeed through tunnel
../../guestbin/ping-once.sh --up -I 192.1.3.209 192.1.2.23
echo done

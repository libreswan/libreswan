../../guestbin/ping-once.sh --down -I 192.1.3.209 192.1.2.23
# wait on OE retransmits and rekeying
sleep 5
# should show tunnel and no shunts
ipsec whack --trafficstatus
ipsec whack --shuntstatus
ipsec _kernel state
ipsec _kernel policy
killall ip > /dev/null 2> /dev/null
cp /tmp/xfrm-monitor.out OUTPUT/road.xfrm-monitor.txt
# ping should succeed through tunnel
../../guestbin/ping-once.sh --up -I 192.1.3.209 192.1.2.23
# pause to let the instance expire, and see if template policy remains
sleep 45
ipsec whack --trafficstatus
sleep 45
ipsec whack --trafficstatus
sleep 45
# idle tunnels should not re-estaliblish, so should be no IPsec SA.
# Template (dir out) for %trap to 192.1.2.23/32 should be there
ipsec whack --trafficstatus
ipsec _kernel policy
echo done

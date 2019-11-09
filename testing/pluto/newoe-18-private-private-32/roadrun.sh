ping -n -c 1 -I 192.1.3.209 192.1.2.23
# wait on OE retransmits and rekeying
sleep 5
# should show tunnel and no shunts
ipsec whack --trafficstatus
ipsec whack --shuntstatus
../../pluto/bin/ipsec-look.sh
killall ip > /dev/null 2> /dev/null
cp /tmp/xfrm-monitor.out OUTPUT/road.xfrm-monitor.txt
# ping should succeed through tunnel
ping -n -c 2 -I 192.1.3.209 192.1.2.23
# pause to let the instance expire, and see if template policy remains
sleep 45
ipsec whack --trafficstatus
sleep 45
ipsec whack --trafficstatus
sleep 45
# idle tunnels should not re-estaliblish, so should be no IPsec SA.
# Template (dir out) for %trap to 192.1.2.23/32 should be there
ipsec whack --trafficstatus
ip xfrm pol
echo done

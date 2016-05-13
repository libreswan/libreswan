ping -n -c 1 192.1.2.23
ping -n -c 1 192.1.2.45
# wait on OE retransmits and rekeying
sleep 5
# should show established tunnel and no bare shunts
ipsec whack --trafficstatus
ipsec whack --shuntstatus
ipsec look
killall ip > /dev/null 2> /dev/null
cp /tmp/xfrm-monitor.out OUTPUT/road.xfrm-monitor.txt
# ping should succeed through tunnel
ping -n -c 2 192.1.2.23
ping -n -c 2 192.1.2.45
echo done

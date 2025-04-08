# trigger OE; should show bare shunt due to local failureshunt
../../guestbin/ping-once.sh --forget -I 192.1.3.209 192.1.2.23
../../guestbin/wait-for.sh --match oe-failing -- ipsec whack --shuntstatus
ipsec whack --trafficstatus
ipsec _kernel state
ipsec _kernel policy
killall ip > /dev/null 2> /dev/null
cp /tmp/xfrm-monitor.out OUTPUT/road.xfrm-monitor.txt
# should fail due to both private hold and remote block policy
../../guestbin/ping-once.sh --down -I 192.1.3.209 192.1.2.23
echo done

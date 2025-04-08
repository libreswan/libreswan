# trigger OE; wait for it to establish with no bare shunts
../../guestbin/ping-once.sh --forget -I 192.1.3.209 192.1.2.23
 ../../guestbin/wait-for.sh --match private-or-clear -- ipsec trafficstatus
ipsec whack --shuntstatus
ipsec _kernel state
ipsec _kernel policy
# kill pluto without sending ike delete
ipsec whack --impair send_no_delete
ipsec stop
sleep 40 # waiting for what?
ipsec start
../../guestbin/wait-until-pluto-started
sleep 10 # waiting for what?
ipsec whack --trafficstatus
ipsec whack --shuntstatus
# ping should succeed through tunnel
../../guestbin/ping-once.sh --forget -I 192.1.3.209 192.1.2.23
../../guestbin/ping-once.sh --up -I 192.1.3.209 192.1.2.23
killall ip > /dev/null 2> /dev/null
cp /tmp/xfrm-monitor.out OUTPUT/road.xfrm-monitor.txt
echo done

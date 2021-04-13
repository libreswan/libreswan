ping -n -q -c 1 -I 192.1.3.209 192.1.2.23
# wait on OE retransmits and rekeying
sleep 5
# should show established tunnel and no bare shunts
ipsec whack --trafficstatus
ipsec whack --shuntstatus
../../guestbin/ipsec-look.sh
# kill pluto without sending ike delete
ipsec whack --impair send-no-delete
ipsec stop
sleep 40
ipsec start
../../guestbin/wait-until-pluto-started
sleep 10
ipsec whack --trafficstatus
ipsec whack --shuntstatus
# ensure for tests acquires expire before our failureshunt=2m
# ping should succeed through tunnel
ping -n -q -c 2 -I 192.1.3.209 192.1.2.23
killall ip > /dev/null 2> /dev/null
cp /tmp/xfrm-monitor.out OUTPUT/road.xfrm-monitor.txt
echo done

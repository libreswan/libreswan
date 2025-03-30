# block policy will cause ping to fail
../../guestbin/ping-once.sh --down -I 192.1.3.209 192.1.2.23
# (pointlessly?) wait on OE retransmits and rekeying
sleep 5
ipsec whack --trafficstatus
ipsec whack --shuntstatus
ipsec _kernel state
ipsec _kernel policy
killall ip > /dev/null 2> /dev/null
cp /tmp/xfrm-monitor.out OUTPUT/road.xfrm-monitor.txt
echo done

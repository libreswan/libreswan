../../guestbin/ping-once.sh --forget 2001:db8:1:2::23
../../guestbin/wait-for.sh --match private-or-clear -- ipsec whack --trafficstatus
../../guestbin/ping-once.sh --up 2001:db8:1:2::23
ipsec whack --trafficstatus
ipsec whack --shuntstatus
killall ip > /dev/null 2> /dev/null
cp /tmp/xfrm-monitor.out OUTPUT/road.xfrm-monitor.txt
echo done

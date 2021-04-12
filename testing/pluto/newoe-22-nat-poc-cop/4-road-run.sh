# no shunts; but triggering OE will create %pass bare shunt
ipsec whack --shuntstatus
../../guestbin/ping-once.sh --forget -I 192.1.3.209 192.1.2.23
../..//guestbin/wait-for.sh --match %pass -- ipsec whack --shuntstatus
# ping should succeed via %pass route
../../guestbin/ping-once.sh --up -I 192.1.3.209 192.1.2.23
# cleanup
killall ip > /dev/null 2> /dev/null
cp /tmp/xfrm-monitor.out OUTPUT/road.xfrm-monitor.txt
echo done

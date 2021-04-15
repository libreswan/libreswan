# trigger OE; should see nothing
../../guestbin/ping-once.sh --forget -I 192.1.3.209 192.1.2.23
ipsec whack --shuntstatus
# now wait for failure shunt to appear
../../guestbin/wait-for.sh --match oe-failing -- ipsec whack --shuntstatus
# ping should fail due to remote block rule
../../guestbin/ping-once.sh --down -I 192.1.3.209 192.1.2.23
# cleanup
killall ip > /dev/null 2> /dev/null
cp /tmp/xfrm-monitor.out OUTPUT/road.xfrm-monitor.txt
echo done

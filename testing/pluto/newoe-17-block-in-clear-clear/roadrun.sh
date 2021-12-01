killall ip > /dev/null 2> /dev/null
cp /tmp/xfrm-monitor.out OUTPUT/road.xfrm-monitor.txt
# ping should fail due to local /32 block rule within /24 clear rule
../../guestbin/ping-once.sh --down -I 192.1.3.209 192.1.2.23
echo done

# bring up OE
ping -n -q -c 4 -I 192.1.3.209 192.1.2.23 > /dev/null
ipsec whack --trafficstatus | sed "s/add_time.*$//"
ipsec stop
ip xfrm state
ipsec start
../../guestbin/wait-until-pluto-started
# give OE policies time to load
../../guestbin/wait-for.sh --match 'loaded 12' -- ipsec auto --status
# bring up OE again
ping -n -q -c 4 -I 192.1.3.209 192.1.2.23 > /dev/null
ipsec whack --trafficstatus | sed "s/add_time.*$//"
killall ip > /dev/null 2> /dev/null
cp /tmp/xfrm-monitor.out OUTPUT/road.xfrm-monitor.txt
echo done

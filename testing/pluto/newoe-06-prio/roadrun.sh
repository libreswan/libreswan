ipsec auto --route road-east-ikev2
# hopefully trigger road-east-ikev2 - not the OE authnull conn
# The ping should also get a reply, proving the IPsec SA was
# preferred over the OE trap policy
ping -n -c 4 -I 192.1.3.209 192.1.2.23
killall ip > /dev/null 2> /dev/null
cp /tmp/xfrm-monitor.out OUTPUT/road.xfrm-monitor.txt
echo done

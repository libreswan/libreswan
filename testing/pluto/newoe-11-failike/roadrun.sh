# trigger OE
ping -n -c 4 -I 192.1.3.209 192.1.2.23
sleep 5
# should see negotiationshunt oe-negotiating
ipsec whack --shuntstatus
sleep 10
# should see failureshunt oe-failed
ipsec whack --shuntstatus
# pings should work plaintext
ping -n -c 4 -I 192.1.3.209 192.1.2.23
killall ip > /dev/null 2> /dev/null
cp /tmp/xfrm-monitor.out OUTPUT/road.xfrm-monitor.txt
echo done

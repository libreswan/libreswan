ping -n -c 1 -I 192.1.3.209 192.1.2.23
# wait on OE retransmits and rekeying
sleep 15
# should show %pass bare shunt
ipsec whack --shuntstatus
killall ip > /dev/null 2> /dev/null
cp /tmp/xfrm-monitor.out OUTPUT/road.xfrm-monitor.txt
# ping should succeed via pass route
ping -n -c 2 -I 192.1.3.209 192.1.2.23
echo done

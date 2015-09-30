ping -n -c 4 -I 192.1.3.209 192.1.2.23
# wait on OE retransmits and rekeying
sleep 5
ipsec whack --trafficstatus
ipsec whack --shuntstatus
ipsec look
# letting acquire and shunt exire
sleep 60
sleep 60
ping -n -c 4 -I 192.1.3.209 192.1.2.23
# state number should have changed from #2 to #4 indicating rekey
ipsec whack --trafficstatus
ipsec look
killall ip > /dev/null 2> /dev/null
cp /tmp/xfrm-monitor.out OUTPUT/road.xfrm-monitor.txt
echo done

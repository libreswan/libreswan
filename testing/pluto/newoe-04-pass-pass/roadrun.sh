ping -n -c 4 -I 192.1.3.209 192.1.2.23
ping -n -c 2 -I 192.1.3.209 7.7.7.7
# wait on OE retransmits and rekeying
sleep 5
ipsec whack --trafficstatus
ipsec whack --shuntstatus
# 7.7.7.7 is %pass, we should be able to ping it
ping -n -c 2 -I 192.1.3.209 7.7.7.7
ipsec look
# letting acquire and shunt exire
sleep 60
ipsec look
sleep 60
ipsec look
sleep 60
ipsec look
killall ip > /dev/null 2> /dev/null
cp /tmp/xfrm-monitor.out OUTPUT/road.xfrm-monitor.txt
echo done

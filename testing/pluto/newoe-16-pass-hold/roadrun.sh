# block policy causing ping to hang?
ping -n -c 2 -I 192.1.3.209 192.1.2.23
sleep 10
# send a ping that still hits negotiationshunt=hold and fails
# wait on OE retransmits and rekeying
ping -n -c 1 -I 192.1.3.209 192.1.2.23
sleep 10
# sleep to let timers install failureshunt=pass
sleep 30
sleep 30
# ping should go out in the clear now and get a reply
ping -n -c 4 -I 192.1.3.209 192.1.2.23
ipsec whack --trafficstatus
ipsec whack --shuntstatus
ipsec look
killall ip > /dev/null 2> /dev/null
cp /tmp/xfrm-monitor.out OUTPUT/road.xfrm-monitor.txt
echo done

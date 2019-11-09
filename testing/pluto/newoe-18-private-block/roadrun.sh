ping -n -c 1 -I 192.1.3.209 192.1.2.23
# wait on OE retransmits and rekeying with retransmit timeout of 5s
sleep 10
# should show bare shunt due to local failureshunt
ipsec whack --trafficstatus
ipsec whack --shuntstatus
../../pluto/bin/ipsec-look.sh
killall ip > /dev/null 2> /dev/null
cp /tmp/xfrm-monitor.out OUTPUT/road.xfrm-monitor.txt
# should fail due to both private hold and remote block policy
ping -n -c 2 -I 192.1.3.209 192.1.2.23
echo done

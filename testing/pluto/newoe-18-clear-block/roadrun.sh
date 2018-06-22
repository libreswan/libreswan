ping -n -c 1 -I 192.1.3.209 192.1.2.23
# wait on OE retransmits and rekeying
sleep 5
ipsec whack --trafficstatus
ipsec whack --shuntstatus
# no tunnel and no bare shunts expected
../../pluto/bin/ipsec-look.sh
killall ip > /dev/null 2> /dev/null
cp /tmp/xfrm-monitor.out OUTPUT/road.xfrm-monitor.txt
# ping should fail due to remote block rule
ping -n -c 2 -I 192.1.3.209 192.1.2.23
echo done

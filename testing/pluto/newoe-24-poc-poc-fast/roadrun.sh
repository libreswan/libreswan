ping -n -q -c 1 -i 0.05  -I 192.1.3.209 192.1.2.23
# wait on OE retransmits and rekeying
sleep 2
ping -n -q -c 3 -i 0.05  -I 192.1.3.209 192.1.2.23
sleep 2
# will show two established tunnels and no shunts
ipsec whack --trafficstatus
ipsec whack --shuntstatus
../../guestbin/ipsec-look.sh
killall ip > /dev/null 2> /dev/null
cp /tmp/xfrm-monitor.out OUTPUT/road.xfrm-monitor.txt
# ping should succeed through tunnel
ping -n -q -c 2 -I 192.1.3.209 192.1.2.23
ipsec whack --trafficstatus
echo done

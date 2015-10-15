# ping causes acquire
ping -n -c 1 -I 192.1.3.209 192.1.2.123
# wait on OE retransmits and rekeying, and delete that causes shunt install
sleep 30
# should show shunt pass because NAT causes OE to fail. east left without any states
ipsec whack --shuntstatus
# ping reply will east's kernel ACQUIRE and get eaten
ping -n -c 1 -I 192.1.3.209 192.1.2.123
# time for IKE from east to fail
sleep 20
# ping should work due to pass shunts on both ends
ping -n -c 3 -I 192.1.3.209 192.1.2.123
killall ip > /dev/null 2> /dev/null
cp /tmp/xfrm-monitor.out OUTPUT/road.xfrm-monitor.txt
echo done

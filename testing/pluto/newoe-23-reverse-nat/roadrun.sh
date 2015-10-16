# ping causes acquire
ping -n -c 1 -I 192.1.3.209 192.1.2.123
# wait on OE retransmits and rekeying, and delete that causes shunt install
sleep 30
# should show shunt pass because NAT causes OE to fail. east left without any states
ipsec whack --shuntstatus
# send a forwarded packet to east so its reply will cause east's kernel to ACQUIRE
# this sends more than one packet so east likely already can reply in the clear
echo "PLAINTEXT" | nc -s 192.1.3.209 192.1.2.123 22
# time for IKE from east to fail
sleep 20
# echo should work due to pass shunts on both ends
echo "PLAINTEXT" | nc -s 192.1.3.209 192.1.2.123 22
killall ip > /dev/null 2> /dev/null
cp /tmp/xfrm-monitor.out OUTPUT/road.xfrm-monitor.txt
echo done

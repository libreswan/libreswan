ping -n -c 1 -I 192.1.3.209 192.1.2.23
# wait on OE retransmits and rekeying, let larval state timeout
sleep 5
# should show no bare shunts or tunnels
ipsec whack --trafficstatus
ipsec whack --shuntstatus
../../guestbin/ipsec-look.sh
killall ip > /dev/null 2> /dev/null
cp /tmp/xfrm-monitor.out OUTPUT/road.xfrm-monitor.txt
ip xfrm state # should be empty
# ping should succeed in the clear
ping -n -c 2 -I 192.1.3.209 192.1.2.23
# should show for our failed attempt at OE
grep "initiate on demand" /tmp/pluto.log
echo done

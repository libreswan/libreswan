ipsec auto --up north-east
ipsec auto --up north-west
ping -n -q -w 4 -c 4 -I 192.0.3.254 192.0.1.254
ping -n -q -w 4 -c 4 -I 192.0.33.254 192.0.1.254 
ipsec whack --trafficstatus
# should be 4
ip -o xfrm state |wc -l
ipsec auto --down north-west
# should be 2
ip -o xfrm state |wc -l
ping -n -q -w 4 -c 4 -I 192.0.33.254 192.0.1.254 
ipsec whack --trafficstatus
ipsec auto --down north-east
# should be 0
ip -o xfrm state |wc -l
ipsec stop
sleep 2
# should be exactly 4
grep "PLUTO_VERB=\'route-client" /tmp/pluto.log  | wc -l
grep "PLUTO_VERB=\'unroute-client" /tmp/pluto.log | wc -l

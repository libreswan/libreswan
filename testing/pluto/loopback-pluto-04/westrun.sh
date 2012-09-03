ipsec auto --up  loopback-04

ip xfrm state
ip xfrm policy
route -n
ipsec auto --delete loopback-04
ip xfrm state
ip xfrm policy
echo done

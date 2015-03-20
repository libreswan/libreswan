ipsec auto --up  loopback-04
ip xfrm state
ip xfrm policy
ip route list
ipsec auto --delete loopback-04
ip xfrm state
ip xfrm policy
echo done

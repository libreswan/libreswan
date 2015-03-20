ipsec auto --up  loopback-01
ip xfrm state
ip xfrm policy
ip route list
ipsec auto --delete loopback-01
ip xfrm state
ip xfrm policy
echo done

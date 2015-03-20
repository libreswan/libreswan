ipsec auto --up  loopback-03-westleft
ip xfrm state
ip xfrm policy
ip route list
ipsec auto --delete loopback-03-westleft
ip xfrm state
ip xfrm policy
echo done

ipsec auto --up  loopback-03-westleft

ip xfrm state
ip xfrm policy
route -n
ipsec auto --delete loopback-03-westleft
ip xfrm state
ip xfrm policy
echo done

ipsec auto --up  loopback-02-westleft

ip xfrm state
ip xfrm policy
route -n
ipsec auto --delete loopback-02-westleft
ip xfrm state
ip xfrm policy
echo done

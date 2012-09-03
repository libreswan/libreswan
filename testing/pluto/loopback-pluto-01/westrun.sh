ipsec auto --up  loopback-01

ip xfrm state
ip xfrm policy
route -n
ipsec auto --delete loopback-01
ip xfrm state
ip xfrm policy
echo done

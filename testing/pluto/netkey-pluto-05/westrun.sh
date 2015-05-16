ipsec auto --up  westnet-eastnet
ip xfrm state
ip xfrm policy
route -n
ipsec auto --delete westnet-eastnet
ip xfrm state
ip xfrm policy
echo done

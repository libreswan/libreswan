ipsec auto --up  westnet-eastnet
ip xfrm policy
ip xfrm state

ping -n -c 4 192.0.2.254

echo done

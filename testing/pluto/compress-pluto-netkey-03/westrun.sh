ipsec auto --up  westnet-eastnet-compress
ping -n -c 4 -I 192.0.1.254 192.0.2.254
ip xfrm state
ip xfrm policy
echo done

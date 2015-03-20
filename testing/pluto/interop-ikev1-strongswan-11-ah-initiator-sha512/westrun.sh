strongswan up westnet-eastnet-ikev1
ping -n -c 4 -I 192.0.1.254 192.0.2.254
# cannot use ipsec look for strongswan
ip xfrm state
ip xfrm pol
echo done

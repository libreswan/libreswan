ipsec auto --up road
# ping will fail until we fix  up-client-v6 and add source address.
ip -6  addr add 2001:db8:0:3:1::0/128 dev lo
ip -6 route add 2001:db8:0:2::/64 via  2001:db8:1:3::254 src 2001:db8:0:3:1::0
ping6 -c 2 -w 5 -I 2001:db8:0:3:1::0 2001:db8:0:2::254
echo done

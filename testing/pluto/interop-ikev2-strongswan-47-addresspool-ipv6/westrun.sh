strongswan up rw-eastnet-ipv6
ping6 -n -q -w 4 -c 4 -I 2001:db8:0:3:1::0 2001:db8:0:2::254
echo done

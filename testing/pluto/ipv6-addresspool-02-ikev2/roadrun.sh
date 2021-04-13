ipsec auto --up road
ping6 -n -q -w 5 -c 2 -I 2001:db8:0:3:1::0 2001:db8:0:2::254
echo done

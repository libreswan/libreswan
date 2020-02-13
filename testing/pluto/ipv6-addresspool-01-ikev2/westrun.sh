ipsec auto --up west
ping6 -c 2 -w 5 -I 2001:db8:0:3:1::0 2001:db8:0:2::254
echo done

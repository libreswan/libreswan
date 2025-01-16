ipsec auto --up westnet-eastnet-6in4
ping6 -n -q -c 4 -I 2001:db8:0:1::254 2001:db8:0:2::254
echo done

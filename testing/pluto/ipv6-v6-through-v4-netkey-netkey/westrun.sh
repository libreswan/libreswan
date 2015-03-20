ipsec auto --up  westnet-eastnet-6in4
# FIXME: should work without -I option
ping6 -n -c 4 -I 2001:db8:0:1::254 2001:db8:0:2::254
ipsec auto --status
ipsec look
echo done

ipsec auto --up  v6-transport
ping6 -n -c 4 -I 2001:db8:1:3::209 2001:db8:1:2::23
ipsec look
echo done

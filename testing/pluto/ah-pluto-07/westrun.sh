ipsec auto --up  westnet-eastnet-ah-md5
ipsec auto --up  westnet-eastnet-ah-sha1
ping -n -c 4 -I 192.0.1.254 192.0.2.254
ping -n -c 4 -I 192.0.1.111 192.0.2.111
echo done

ipsec auto --up road
# ping will fail until we fix  up-client-v6 and add source address.
ping -c 2 -w 5 192.0.2.254
echo done

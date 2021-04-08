# bring up the tunnel
strongswan up westnet-eastnet-ikev2
strongswan status | grep -v libcurl
ping -n -q -c 8 -I 192.0.1.254 192.0.2.254
sleep 5
strongswan status
echo done

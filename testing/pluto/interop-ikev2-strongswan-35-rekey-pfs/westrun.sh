# bring up the tunnel
strongswan up westnet-eastnet-ikev2
strongswan status
ping -n -c 8 -I 192.0.1.254 192.0.2.254
strongswan status
echo done

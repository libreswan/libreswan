# bring up the tunnel
strongswan up westnet-eastnet-ikev2
strongswan status
ping -n -c 4 -I 192.0.1.254 192.0.2.254
swanctl --rekey --child  westnet-eastnet-ikev2
sleep 15
ping -n -c 4 -I 192.0.1.254 192.0.2.254
# should be rekeyed and old one deleted
# noitce westnet-eastnet-ikev2{2} is the newest one
strongswan status
swanctl --rekey --child  westnet-eastnet-ikev2
sleep 15
ping -n -c 4 -I 192.0.1.254 192.0.2.254
# second rekey and old one deleted
# noitce westnet-eastnet-ikev2{3} is the newest one
strongswan status
echo done

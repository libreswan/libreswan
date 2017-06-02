# bring up the tunnel
strongswan up westnet-eastnet-ikev2
strongswan status
ping -n -c 4 -I 192.0.1.254 192.0.2.254
echo "sleep 25 seconds. to rekey of child sa"
sleep 25
ping -n -c 4 -I 192.0.1.254 192.0.2.254
strongswan status
echo "sleep another 25 seconds. second rekey of child sa"
sleep 25
ping -n -c 4 -I 192.0.1.254 192.0.2.254
strongswan status
echo done

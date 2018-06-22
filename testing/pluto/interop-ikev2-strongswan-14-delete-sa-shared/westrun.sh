strongswan up westnet-eastnet-ikev2
strongswan up westnet-eastnet2-ikev2
ping -n -c 4 -I 192.0.1.254 192.0.2.254
strongswan down westnet-eastnet-ikev2
sleep 1
strongswan down westnet-eastnet2-ikev2
sleep 3
echo done

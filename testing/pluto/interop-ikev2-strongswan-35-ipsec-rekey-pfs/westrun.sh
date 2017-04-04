# bring up the tunnel
strongswan up westnet-eastnet-ikev2
strongswan status
ping -n -c 6 -I 192.0.1.254 192.0.2.254
echo "sleep 80 sec to ike to rekey "
sleep 50
sleep 30
ping -n -c 4 -I 192.0.1.254 192.0.2.254
echo done

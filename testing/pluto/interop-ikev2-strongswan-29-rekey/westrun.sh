# bring up the tunnel
strongswan up westnet-eastnet-ikev2
ping -n -c 4 -I 192.0.1.254 192.0.2.254
strongswan status
ping -n -c 4 -I 192.0.1.254 192.0.2.254
echo "sleep 30 sec to ike to rekey "
sleep 30
ping -n -c 4 -I 192.0.1.254 192.0.2.254
strongswan status
echo "sleep 30 sec to ike to rekey "
sleep 30
ping -n -c 4 -I 192.0.1.254 192.0.2.254
echo done

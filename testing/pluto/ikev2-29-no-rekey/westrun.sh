ipsec auto --up  westnet-eastnet-ikev2
ping -n -c 4 -I 192.0.1.254 192.0.2.254
ipsec status
echo "Waiting 110 seconds... for the tunnel to break"
sleep 60
sleep 50
ipsec status
ipsec whack --trafficstatus
echo done

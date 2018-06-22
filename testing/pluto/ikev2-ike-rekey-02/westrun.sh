ipsec auto --up west
ping -W 4 -n -c 4 -I 192.0.1.254 192.0.2.254
ipsec whack --trafficstatus
echo "sleep 50"
sleep 50
ping -W 4 -n -c 4 -I 192.0.1.254 192.0.2.254
ipsec whack --trafficstatus
ipsec status |grep STATE_
echo "sleep 50"
sleep 50
ping -W 4 -n -c 4 -I 192.0.1.254 192.0.2.254
echo done

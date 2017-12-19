ipsec auto --up west
ping -W 4 -n -c 4 -I 192.0.1.254 192.0.2.254
ipsec whack --trafficstatus
echo "sleep 30"
sleep 30
ping -W 4 -n -c 4 -I 192.0.1.254 192.0.2.254
ipsec whack --trafficstatus
sleep 20
ping -W 4 -n -c 4 -I 192.0.1.254 192.0.2.254
echo done

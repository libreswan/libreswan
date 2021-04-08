ipsec auto --up west
ping -n -q -W 4 -c 4 -I 192.0.1.254 192.0.2.254
ipsec whack --trafficstatus
echo "sleep 40"
sleep 40
ping -n -q -W 4 -c 4 -I 192.0.1.254 192.0.2.254
ipsec whack --trafficstatus
ping -n -q -W 4 -c 4 -I 192.0.1.254 192.0.2.254
echo done

ipsec auto --up west
ping -n -q -W 4 -c 4 -I 192.0.1.254 192.0.2.254
ipsec whack --trafficstatus
echo "sleep 31"
sleep 31
ping -n -q -W 4 -c 4 -I 192.0.1.254 192.0.2.254
ipsec whack --trafficstatus
echo "sleep 31"
sleep 20
ping -n -q -W 4 -c 4 -I 192.0.1.254 192.0.2.254
echo done

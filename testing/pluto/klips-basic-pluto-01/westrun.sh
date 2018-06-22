ipsec auto --up  westnet-eastnet
sleep 1
ping -n -c 4 -I 192.0.1.254 192.0.2.254
ipsec whack --trafficstatus
ipsec auto --down  westnet-eastnet
echo done

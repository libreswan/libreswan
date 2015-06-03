ipsec auto --up  westnet-eastnet-ikev2
ping -n -c 4 -I 192.0.1.254 192.0.2.254
ipsec eroute
# wait for rekey event
sleep 20
sleep 20
sleep 20
sleep 20
ipsec eroute
ipsec whack --trafficstatus
echo done

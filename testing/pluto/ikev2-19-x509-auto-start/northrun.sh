ipsec auto --up northnet-eastnet-ipv4
ping -n -c 2 -I 192.0.3.254 192.0.2.254
ipsec whack --trafficstatus
# waiting 2 minutes in chunks of 15 seconds
sleep 15
sleep 15
sleep 15
sleep 15
echo one minute
sleep 15
sleep 15
sleep 15
sleep 15
echo two minutes
ipsec auto --status | grep northnet-eastnet-ipv4
ping -n -c 2 -I 192.0.3.254 192.0.2.254
echo done

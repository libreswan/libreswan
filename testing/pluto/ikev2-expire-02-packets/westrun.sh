ipsec auto --up west
# pings will not trigger rekey
ping -n -q -c 16 -I 192.0.1.254 192.0.2.254
# expect #2 IPsec original Child SA
ipsec trafficstatus
# next pings will go over and initiate a rekey
ping -n -q -c 8 -I 192.0.1.254 192.0.2.254
sleep 5
# expect only #3 IPsec first rekeyed Child SA
ipsec trafficstatus
ping -n -q -c 10 -I 192.0.1.254 192.0.2.254
sleep 5
# expect only #4 IPsec second rekeyed Child SA
ipsec trafficstatus
echo done

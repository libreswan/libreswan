ipsec auto --up west
# pings will get to almost rekey, but rekey wouldn't trigger
ping -n -q -c 18 -I 192.0.1.254 192.0.2.254
: ==== cut ====
ip -s xfrm state
: ==== tuc ====
# expect ony #2 IPsec original Child SA
ipsec trafficstatus
# next pings will go over and initiate a rekey
ping -n -q -c 8 -I 192.0.1.254 192.0.2.254
sleep 5
# expect only #3 IPsec first rekeyed Child SA
# #2 should have expired and replaced.
ipsec trafficstatus
ping -n -q -c 25 -I 192.0.1.254 192.0.2.254
# expect only #4 IPsec second rekeyed Child SA
sleep 5
ipsec trafficstatus
echo done

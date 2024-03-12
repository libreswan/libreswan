ipsec auto --up west

# find out the actual number of packets
actual=$(sed -n -e 's/.* ipsec-max-bytes.* actual-limit=\([0-9]*\).*/\1/ p' /tmp/pluto.log | head -1)
echo $actual

# pings will get to almost rekey, but rekey wouldn't trigger; expect
# only #2 IPsec original Child SA; expression truncates but that is
# good enough
ping -n -q -c $((actual / 84)) -I 192.0.1.254 192.0.2.254
: ==== cut ====
ip -s xfrm state
: ==== tuc ====

ipsec trafficstatus

# next pings will go over and initiate a rekey expect only #3 IPsec
# first rekeyed Child SA #2 should have expired and replaced.
ping -n -q -c $((actual / 84)) -I 192.0.1.254 192.0.2.254
sleep 5
ipsec trafficstatus

# expect only #4 IPsec second rekeyed Child SA
ping -n -q -c $((actual / 84)) -I 192.0.1.254 192.0.2.254
sleep 5
ipsec trafficstatus

echo done

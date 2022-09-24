ipsec auto --up west

# find out the actual number of packets
actual=$(sed -n -e 's/.* ipsec-max-packets.* actual-limit=\([0-9]*\).*/\1/ p' /tmp/pluto.log | head -1)
echo $actual

# $actual-1 pings will not trigger rekey; expect #2 to remain
ping -n -q -c $((actual - 1)) -I 192.0.1.254 192.0.2.254
ipsec trafficstatus

# next ping will go over and initiate a rekey; and then further pings
# go to #3
ping -n -q -c ${actual} -I 192.0.1.254 192.0.2.254
sleep 5
ipsec trafficstatus

# and again
ping -n -q -c ${actual} -I 192.0.1.254 192.0.2.254
sleep 5
ipsec trafficstatus

echo done

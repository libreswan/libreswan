ipsec auto --up road

# Monitor the XFRMI ipsec1 interface
../../guestbin/tcpdump.sh --start -i ipsec1

# rekey; detaches after old Child SA is gone
ipsec whack --rekey-child --name road

# rekey; detaches after old Child SA is gone
ipsec whack --rekey-child --name road

# give TCPDUMP some time before shutting it down; output should be
# empty as only IKE packets were sent
sleep 5
../../guestbin/tcpdump.sh --stop -i ipsec1

# Check a re-add flushes old ipsec1.  TCPDUMP is stopped before doing
# this so it won't asynchronously log that it lost ipsec1.
ipsec auto --add road
ipsec auto --up road

echo done

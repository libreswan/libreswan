# east should have brought down but NOT re-established the tunnel
ipsec whack --trafficstatus
# can be seen on east logs
hostname | grep west > /dev/null || grep "IKEv2 liveness action:" /tmp/pluto.log

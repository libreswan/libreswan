../../guestbin/xfrmcheck.sh

# traffic should be 0 bytes in both directions - no ESP
ipsec whack --trafficstatus

# EAST should not have ESP packets - no IKE over ESP
../../guestbin/tcpdump.sh --stop -i eth1


../../guestbin/xfrmcheck.sh

# traffic should be 0 bytes in both directions - no ESP
ipsec whack --trafficstatus

# ROAD should not have ESP packets - no IKE over ESP
sleep 5
../../guestbin/tcpdump.sh --stop -i eth0

../../guestbin/ip.sh -s link show ipsec1
ip rule show
../../guestbin/ip.sh route show table 50
../../guestbin/ip.sh route

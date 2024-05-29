../../guestbin/xfrmcheck.sh

# traffic should be 0 bytes in both directions - no ESP
ipsec whack --trafficstatus

# ROAD should not have ESP packets - no IKE over ESP
sleep 5
../../guestbin/tcpdump.sh --stop -i eth0

ip -s link show ipsec1
ip rule show
../../guestbin/route.sh show table 50
../../guestbin/route.sh

../../guestbin/xfrmcheck.sh
# traffic should be 0 bytes in both directions - no ESP
ipsec whack --trafficstatus
# neither east nor road should have ESP packets - no IKE over ESP
../../guestbin/tcpdump.sh --stop -i eth1 --host east
../../guestbin/tcpdump.sh --stop -i eth0 --host road
# next tcpdump outout should be empty as only IKE packets were sent
../../guestbin/tcpdump.sh --stop -i ipsec1 --host road
hostname | grep road > /dev/null && ip -s link show ipsec1
hostname | grep road > /dev/null && ip rule show
hostname | grep road > /dev/null && ip route show table 50
hostname | grep road > /dev/null && ip route

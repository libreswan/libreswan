../../guestbin/xfrmcheck.sh
# traffic should be 0 bytes in both directions
ipsec whack --trafficstatus
# on east eth1 should not have ESP packets
../../guestbin/tcpdump.sh --stop -i eth1 --host east
../../guestbin/tcpdump.sh --stop -i eth0 --host road
# next tcpdump outout should be empty
../../guestbin/tcpdump.sh --stop -i ipsec1 --host road
hostname | grep east > /dev/null && ip -s link show ipsec1
hostname | grep east > /dev/null && ip rule show
hostname | grep east > /dev/null && ip route show table 50
hostname | grep east > /dev/null && ip route

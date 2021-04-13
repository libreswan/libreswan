../../guestbin/xfrmcheck.sh
# traffic should be 0 bytes in both directions
ipsec whack --trafficstatus
../../guestbin/tcpdump.sh --stop --host east
hostname | grep east > /dev/null && ip -s link show ipsec1
hostname | grep east > /dev/null && ip rule show
hostname | grep east > /dev/null && ip route show table 50
hostname | grep east > /dev/null && ip route

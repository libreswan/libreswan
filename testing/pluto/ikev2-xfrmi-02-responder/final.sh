../../guestbin/xfrmcheck.sh
# traffic should be 0 bytes in both directions
ipsec whack --trafficstatus
hostname | grep east > /dev/null && ../../guestbin/tcpdump.sh --stop -i eth1
hostname | grep east > /dev/null && ip -s link show ipsec1
hostname | grep east > /dev/null && ip rule show
hostname | grep east > /dev/null && ../../guestbin/route.sh show table 50
hostname | grep east > /dev/null && ../../guestbin/route.sh

../../guestbin/xfrmcheck.sh
# traffic should be 0 bytes in both directions
ipsec whack --trafficstatus
hostname | grep east > /dev/null && ../../guestbin/tcpdump.sh --stop -i eth1
hostname | grep east > /dev/null && ../../guestbin/ip.sh -s link show ipsec1
hostname | grep east > /dev/null && ../../guestbin/ip.sh rule show
hostname | grep east > /dev/null && ../../guestbin/ip.sh route show table 50
hostname | grep east > /dev/null && ../../guestbin/ip.sh route

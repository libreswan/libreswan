../../guestbin/xfrmcheck.sh
# traffic should be 0 bytes in both directions
ipsec whack --trafficstatus
../../guestbin/tcpdump.sh --stop

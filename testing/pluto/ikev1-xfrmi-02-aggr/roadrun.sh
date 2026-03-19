ipsec auto --up road
# ../../guestbin/ip.sh rule add prio 100 to 192.1.2.23/32 not fwmark 1/0xffffffff lookup 50
# sleep 2
# ../../guestbin/ip-route.sh add table 50 192.1.2.23/32 dev ipsec1 src 192.1.3.209
../../guestbin/ping-once.sh --up 192.1.2.23
../../guestbin/ip.sh -s link show ipsec1
../../guestbin/ip.sh rule show
../../guestbin/ip-route.sh show table 50
../../guestbin/ip-route.sh
echo done

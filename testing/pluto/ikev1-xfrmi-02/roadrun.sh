ipsec auto --up road
# ip rule add prio 100 to 192.1.2.23/32 not fwmark 1/0xffffffff lookup 50
# sleep 2
# ../../guestbin/route.sh add table 50 192.1.2.23/32 dev ipsec1 src 192.1.3.209
../../guestbin/ping-once.sh --up 192.1.2.23
ip -s link show ipsec1
ip rule show
../../guestbin/route.sh show table 50
../../guestbin/route.sh
echo done

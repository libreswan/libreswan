ipsec auto --up road
# ../../guestbin/ip.sh rule add prio 100 to 192.1.2.23/32 not fwmark 1/0xffffffff lookup 50
# sleep 2
# ../../guestbin/ip.sh route add table 50 192.1.2.23/32 dev ipsec0 src 192.1.3.209
../../guestbin/ping-once.sh --up 192.1.2.23
../../guestbin/ip.sh -s link show ipsec0
../../guestbin/ip.sh rule show
../../guestbin/ip.sh route show table 50
../../guestbin/ip.sh route
# check if_id and mark in ip xfrm state
ipsec _kernel state
ipsec trafficstatus
# check if delete removes all policies without errors
ipsec auto --delete road
ipsec _kernel state
ip xfrm policy
echo done

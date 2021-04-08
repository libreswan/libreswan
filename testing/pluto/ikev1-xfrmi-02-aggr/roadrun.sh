ipsec auto --up road
# ip rule add prio 100 to 192.1.2.23/32 not fwmark 1/0xffffffff lookup 50
# sleep 2
# ip route add table 50 192.1.2.23/32 dev ipsec1 src 192.1.3.209
ping -n -q -w 4 -c 4 192.1.2.23
ip -s link show ipsec1
ip rule show
ip route show table 50
ip route
echo done

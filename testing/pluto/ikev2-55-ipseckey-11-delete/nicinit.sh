setenforce Permissive 2>/dev/null
/testing/guestbin/nic-dnssec.sh start
# Delay only DNS replies sent to road.  nft marks (and counts) them,
# tc netem does the actual delaying; everything else is untouched.
dev=$(ip -o addr show to 192.1.3.254 | awk '{print $2}')
nft add table inet dly
nft add counter inet dly delayed
nft add chain inet dly out '{ type filter hook output priority mangle; }'
nft add rule inet dly out ip daddr 192.1.3.209 udp sport 53 counter name delayed meta mark set 1
/sbin/tc qdisc add dev $dev root handle 1: prio
/sbin/tc qdisc add dev $dev parent 1:1 handle 10: netem delay 3000ms
/sbin/tc filter add dev $dev parent 1: protocol ip prio 1 handle 1 fw flowid 1:1
echo done

ip addr show dev eth1 | grep 192.1.33.254 || ip addr add 192.1.33.254/24 dev eth1
iptables -t nat -F
iptables -F
iptables -X
echo initdone
: ==== end ====

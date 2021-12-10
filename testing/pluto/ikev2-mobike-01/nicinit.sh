ip addr show dev eth2 | grep 192.1.8.254 || ip addr add 192.1.8.254/24 dev eth2
iptables -t nat -F
iptables -F
iptables -X
echo initdone
: ==== end ====

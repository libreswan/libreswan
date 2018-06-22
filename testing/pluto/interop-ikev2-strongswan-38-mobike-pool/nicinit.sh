iptables -t nat -F
iptables -F
iptables -X
# NAT
ip addr show dev eth1 | grep 192.1.33.254 || ip addr add 192.1.33.254/24 dev eth1
iptables -t nat -A POSTROUTING -p udp --sport 4500 -j SNAT --to-source 192.1.2.254:3500-3700
iptables -t nat -A POSTROUTING -p udp --sport 500 -j SNAT --to-source 192.1.2.254:2500-2700
iptables -t nat -A POSTROUTING --destination 0.0.0.0/0 -j SNAT --to-source 192.1.2.254
iptables -t nat -L -n
iptables -L -n
echo initdone
: ==== end ====

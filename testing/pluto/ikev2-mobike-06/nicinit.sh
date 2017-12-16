ip addr show dev eth1 | grep 192.1.33.254 || ip addr add 192.1.33.254/24 dev eth1
ip addr show dev eth1 | grep 192.1.2.250 || ip addr add 192.1.3.250/24 dev eth0
iptables -t nat -F
iptables -F
iptables -X
iptables -t nat -L -n | grep 192.1.3.209 || iptables -t nat -A POSTROUTING -s 192.1.3.209/32 -p udp -j SNAT --to-source 191.1.2.254:11000-12000 && iptables -t nat -A POSTROUTING -s 192.1.3.209/32 -j SNAT --to-source 192.1.2.254
iptables -t nat -L -n | grep 192.1.33.222 || iptables -t nat -A POSTROUTING -s 192.1.33.222/32 -p udp -j SNAT --to-source 191.1.2.250:33000-34000 && iptables -t nat -A POSTROUTING -s 192.1.33.222/32 -j SNAT --to-source 192.1.2.250
echo initdone
: ==== end ====

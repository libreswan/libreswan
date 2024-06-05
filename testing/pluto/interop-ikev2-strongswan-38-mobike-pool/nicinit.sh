../../guestbin/ip.sh address show dev eth2 | grep 192.1.33.254 || ../../guestbin/ip.sh address add 192.1.33.254/24 dev eth2
../../guestbin/ip.sh address show dev eth2 | grep 192.1.2.250 || ../../guestbin/ip.sh address add 192.1.3.250/24 dev eth1
iptables -t nat -F
iptables -F
iptables -X
# port for the first address
iptables -t nat -A POSTROUTING -s 192.1.3.209 -p udp --sport 4500 -j SNAT --to-source 192.1.2.254:3503-3509
iptables -t nat -A POSTROUTING -s 192.1.3.209 -p udp --sport 500 -j SNAT --to-source 192.1.2.254:2503-2509
# for the second address use different port range
iptables -t nat -A POSTROUTING -s 192.1.33.222 -p udp --sport 4500 -j SNAT --to-source 192.1.2.254:6503-6509
iptables -t nat -A POSTROUTING -s 192.1.33.222 -p udp --sport 500 -j SNAT --to-source 192.1.2.254:5503-5509
iptables -t nat -A POSTROUTING --destination 0.0.0.0/0 -j SNAT --to-source 192.1.2.254
iptables -t nat -L -n
iptables -L -n
echo initdone
: ==== end ====

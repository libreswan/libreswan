../../guestbin/ip.sh address show dev eth2 | grep 192.1.33.254 || ../../guestbin/ip.sh address add 192.1.33.254/24 dev eth2
iptables -t nat -F
iptables -F
iptables -X
echo initdone
: ==== end ====

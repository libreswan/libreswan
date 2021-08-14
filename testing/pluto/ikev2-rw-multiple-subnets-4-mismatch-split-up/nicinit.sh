iptables -t nat -F
iptables -F
iptables -t nat -L
# NAT
../../guestbin/nic-nat.sh 192.1.3.0/24 192.1.2.254 50000
iptables -I FORWARD 1 --proto 50 -j DROP
echo done
: ==== end ====

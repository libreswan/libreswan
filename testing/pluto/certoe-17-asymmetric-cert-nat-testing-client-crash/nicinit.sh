iptables -t nat -F
iptables -F
../../guestbin/nic-nat.sh 192.1.3.0/24 192.1.2.254 50000

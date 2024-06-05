iptables -t nat -F
iptables -F
../../guestbin/ip.sh address add 192.1.3.130/24 dev eth2
# Destination NAT to east's address not the port
iptables -t nat -A PREROUTING -d 192.1.3.130 -j DNAT --to-destination 192.1.2.23

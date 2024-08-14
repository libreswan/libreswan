iptables --flush
iptables --table nat --flush
iptables --delete-chain
iptables --table nat --delete-chain
# NAT to NIC's address
iptables -t nat -A POSTROUTING -s 192.1.3.0/24 -p udp --sport 4500  -j SNAT --to-source 192.1.2.254:45000
iptables -t nat -A POSTROUTING -s 192.1.3.0/24 -j SNAT --to-source 192.1.2.254

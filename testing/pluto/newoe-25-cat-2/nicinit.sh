iptables -t nat -F
iptables -F
# NAT to NIC's address
iptables -t nat -A POSTROUTING -s 192.1.3.0/24 -j SNAT --to-source 192.1.2.254

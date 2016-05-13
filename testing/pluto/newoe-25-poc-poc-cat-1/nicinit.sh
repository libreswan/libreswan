iptables -t nat -F
iptables -F
# NAT
iptables -t nat -A POSTROUTING --source 192.1.3.0/24 --destination 0.0.0.0/0 -j SNAT --to-source 192.1.2.254

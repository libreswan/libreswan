#/usr/sbin/named
iptables -F
# put east behind NAT portforward
iptables -I PREROUTING -t nat -i eth1 -p udp --dport  500 -j DNAT --to 192.1.2.23:500
iptables -I PREROUTING -t nat -i eth1 -p udp --dport 4500 -j DNAT --to 192.1.2.23:4500
# and regular NAT and ESP dropping gateway
iptables -I POSTROUTING -t nat -o eth1 -j MASQUERADE -s 192.1.2.23/32
iptables -I FORWARD -p esp -j DROP


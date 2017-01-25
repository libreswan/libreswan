#/usr/sbin/named
iptables -F
iptables -F -t nat
# put east behind NAT portforward
iptables -I PREROUTING -t nat -i eth1 -p udp --dport  500 -j DNAT --to 192.1.2.23:500
iptables -I PREROUTING -t nat -i eth1 -p udp --dport 4500 -j DNAT --to 192.1.2.23:4500
iptables -I PREROUTING -t nat -i eth1 -p tcp --dport  22 -j DNAT --to 192.1.2.23:22
# and behind NAT
iptables -I POSTROUTING -t nat -j SNAT -s 192.1.2.23/32 --to 192.1.2.123

: ==== end ====

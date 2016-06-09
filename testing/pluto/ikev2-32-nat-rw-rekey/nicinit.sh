iptables -t nat -F
iptables -F
iptables -t nat -L
# NAT
iptables -t nat -A POSTROUTING -s 192.1.3.0/24 -p udp --sport 4500 -j SNAT --to-source 192.1.2.254:3500-3700
iptables -t nat -A POSTROUTING -s 192.1.3.0/24 -p udp --sport 500 -j SNAT --to-source 192.1.2.254:2500-2700
iptables -t nat -A POSTROUTING --source 192.1.3.0/24 --destination 0.0.0.0/0 -j SNAT --to-source 192.1.2.254
iptables -I FORWARD 1 --proto 50 -j LOGDROP
echo done

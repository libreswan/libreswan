iptables -t nat -F
iptables -F
iptables -t nat -L
iptables -I FORWARD -s 192.1.2.23 -p udp --sport 500 -j DROP
echo done

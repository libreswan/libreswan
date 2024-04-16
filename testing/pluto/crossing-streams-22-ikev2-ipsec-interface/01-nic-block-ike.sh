iptables -t nat -F
iptables -F
iptables -I FORWARD -s 0.0.0.0/0 -d 0.0.0.0/0 -p udp --dport 500 -j DROP
iptables -t nat -L
echo done
: ==== end ====

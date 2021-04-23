iptables -t nat -F
iptables -F
iptables -t nat -L
sysctl -w net.ipv6.conf.all.forwarding=1
echo done
: ==== end ====

iptables -t nat -F
iptables -F
# NAT road. north will not be nated
iptables -t nat -A POSTROUTING -s 192.1.3.209/32 -j SNAT --to-source 192.1.2.254
: ==== end ====

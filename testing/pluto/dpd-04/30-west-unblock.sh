# remove the block
iptables -D INPUT -s 192.1.2.23/32 -d 0/0 -j DROP
iptables -D OUTPUT -s 192.1.2.45/32 -d 0/0 -j DROP

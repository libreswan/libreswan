# to ensure no packets sneak through a %pass shunt, drop them on nic
iptables -I FORWARD -s 0.0.0.0/0 -d 0.0.0.0/0 -p icmp -j DROP

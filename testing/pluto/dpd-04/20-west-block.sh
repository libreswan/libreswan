# Create the block; wait for DPD to trigger
iptables -I OUTPUT -s 192.1.2.45/32 -d 0/0 -j DROP
iptables -I INPUT -s 192.1.2.23/32 -d 0/0 -j DROP

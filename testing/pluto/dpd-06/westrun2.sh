# remove the block
iptables -D INPUT -s 192.1.2.23/32 -d 0/0 -j DROP
iptables -D OUTPUT -d 192.1.2.23/32 -s 0/0 -j DROP
sleep 10
# Tunnel should be back up now
ipsec whack --trafficstatus
echo done


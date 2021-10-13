# Tunnel should be still be up because this end doesn't do DPD
ipsec whack --trafficstatus
# Remove the Blockage
iptables -D INPUT -s 192.1.2.23/32 -d 0/0 -j DROP
iptables -D OUTPUT -d 192.1.2.23/32 -s 0/0 -j DROP

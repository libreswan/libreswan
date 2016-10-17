ipsec auto --up north-east-x509-ipv4
ping -n -c4 -I 192.0.2.100 192.1.2.23
ipsec whack --trafficstatus
# Setting up block via iptables
iptables -I INPUT -s 192.1.2.23/32 -d 0/0 -j DROP
iptables -I OUTPUT -d 192.1.2.23/32 -s 0/0 -j DROP
sleep 60
ipsec whack --trafficstatus
echo "initdone"

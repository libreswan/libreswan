ping -n -q -w 4 -c 4 192.0.2.254
ipsec trafficstatus
ipsec auto --up north-east
ping -n -q -w 4 -c 4 192.0.2.254
ipsec trafficstatus
ip -s link show ipsec2
ip route
ip route add 192.0.2.0/24 dev ipsec2
ping -n -q -w 4 -c 4 192.0.2.254
ip -s link show ipsec2
ipsec trafficstatus
echo "initdone"

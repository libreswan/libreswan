ipsec auto --up  westnet-eastnet-vti
ip tunnel add west-east mode vti remote 192.1.2.23 local 192.1.2.45 key 20
ip link set west-east up
sysctl -w net.ipv4.conf.west-east.disable_policy=1
sysctl -w net.ipv4.conf.west-east.rp_filter=0
sysctl -w net.ipv4.conf.west-east.forwarding=1
# show ping fails because it is not routed into vti device
ping -n -c 4 -I 192.0.1.254 192.0.2.254
ipsec whack --trafficstatus
ip route add 192.0.2.0/24 dev west-east
# ping now succeeds and packets are encrypted
ping -n -c 4 -I 192.0.1.254 192.0.2.254
ipsec whack --trafficstatus
# show iptables works on vti interfaces
iptables -I OUTPUT -p icmp -j REJECT -o west-east
ping -n -c 4 -w 2 -I 192.0.1.254 192.0.2.254
ipsec whack --trafficstatus
echo done

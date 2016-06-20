ipsec auto --up  westnet-eastnet-vti-01
ipsec auto --up  westnet-eastnet-vti-02
ip tunnel add west-east mode vti remote 192.1.2.23 local 192.1.2.45 ikey 20 okey 21
ip link set west-east up
sysctl -w net.ipv4.conf.west-east.disable_policy=1
sysctl -w net.ipv4.conf.west-east.rp_filter=0
sysctl -w net.ipv4.conf.west-east.forwarding=1
ip route add 192.0.2.0/24 dev west-east
ip route add 10.0.2.0/24 dev west-east
ping -n -c 4 -I 192.0.1.254 192.0.2.254
ping -n -c 4 -I 10.0.1.254 10.0.2.254
ipsec whack --trafficstatus
echo done

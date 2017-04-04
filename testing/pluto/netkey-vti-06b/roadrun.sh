ip addr add 192.0.3.254/24 dev eth0
ipsec auto --up  road-east-vti
# since we have vti-routing=no, no marking, so unencryted pacets are dropped
#ping -n -c 4 192.1.2.23
ping -n -c 4 -I 192.0.3.254 192.1.2.23
ipsec whack --trafficstatus
#ip route add 192.1.2.23/24 dev vti0
ip ro add 192.0.2.0/24 dev vti0
# now packets into vti0 device will get marked, and encrypted and counted
#ping -n -c 4 192.1.2.23
ping -n -c 4 -I 192.0.3.254 192.1.2.23
ipsec whack --trafficstatus
echo done

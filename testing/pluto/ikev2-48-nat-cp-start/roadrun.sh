sleep 4
ip -4 route
# ipsec will configure 192.0.2.1 on eth0
ip addr show  dev eth0
ping -n -c 2 192.1.2.23
ipsec whack --trafficstatus
ipsec auto --down westnet-eastnet-ipv4-psk-ikev2
#check if the address, 192.0.2.1, is removed
ip addr show  dev eth0
echo done

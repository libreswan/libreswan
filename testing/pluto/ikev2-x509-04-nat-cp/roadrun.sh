ipsec auto --up rw
# ipsec will configure 100.64.0.x on eth0
ip addr show  dev eth0
ping -n -q -c 2 192.0.2.254
ipsec whack --trafficstatus
ipsec auto --down rw
#check if the address is removed
ip addr show  dev eth0
echo done

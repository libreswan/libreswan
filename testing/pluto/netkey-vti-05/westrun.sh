ipsec auto --up  westnet-eastnet-vti
ping -n -c 4 -I 192.1.99.1 192.1.99.254
ipsec whack --trafficstatus
ip addr show dev vti0
echo done

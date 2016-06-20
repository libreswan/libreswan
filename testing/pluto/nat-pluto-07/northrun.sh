ipsec auto --up northnet-eastnet-nat
ping -c 4 -n -I 192.0.3.254 192.0.2.254
ipsec whack --trafficstatus
echo done

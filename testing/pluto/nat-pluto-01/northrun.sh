ipsec auto --up northnet-eastnet-nat
ping -n -c 3 -I 192.0.3.254 192.0.2.254
ipsec whack --trafficstatus
echo done

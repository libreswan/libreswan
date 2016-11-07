ipsec auto --up road-eastnet-nat
ping -n -c 4 192.0.2.254
ipsec whack --trafficstatus
echo done

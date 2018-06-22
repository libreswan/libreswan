ipsec auto --up road-eastnet
ping -w 4 -n -c4 192.0.2.254
ipsec whack --trafficstatus
echo done

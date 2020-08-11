ipsec auto --up eastnet-any
ping -n -c 4 -I 100.64.13.2 192.0.2.254
ipsec whack --trafficstatus
# trigger rekey
ipsec auto --up eastnet-any
echo done

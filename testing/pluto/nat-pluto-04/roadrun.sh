ipsec auto --up road-eastnet-nat
# 192.0.2.219 as source ip should be picked up automatically
ping -c 4 -n 192.0.2.254
ipsec whack --trafficstatus
echo done

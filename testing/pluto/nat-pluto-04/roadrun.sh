ipsec auto --up road-eastnet-nat
# 192.0.2.219 as source ip should be picked up automatically
../../guestbin/ping-once.sh --up 192.0.2.254
ipsec whack --trafficstatus
echo done

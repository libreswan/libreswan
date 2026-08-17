ipsec auto --up northnet-eastnet-nonat
../../guestbin/ping-once.sh --up -I 198.18.66.254 192.0.2.254
ipsec trafficstatus
echo done

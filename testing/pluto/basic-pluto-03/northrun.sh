ipsec auto --up northnet-eastnet-nonat
../../pluto/bin/ping-once.sh --up -I 192.0.3.254 192.0.2.254
ipsec trafficstatus
echo done

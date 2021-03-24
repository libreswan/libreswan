ipsec auto --up westnet-eastnet
../../pluto/bin/ping-once.sh --up -I 192.0.1.254 192.0.2.254
ipsec whack --trafficstatus
ipsec auto --down  westnet-eastnet
echo done

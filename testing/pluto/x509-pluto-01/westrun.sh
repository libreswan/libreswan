ipsec auto --up westnet-eastnet-x509-nosend
../../pluto/bin/ping-once.sh --up -I 192.0.1.254 192.0.2.254
ipsec whack --trafficstatus
echo done

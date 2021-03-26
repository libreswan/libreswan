ipsec auto --up westnet-eastnet-ikev1
../../pluto/bin/ping-once.sh --up 192.1.2.23
ipsec whack --trafficstatus
echo done

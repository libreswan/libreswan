ipsec auto --up westnet-eastnet
../../pluto/bin/ping-once.sh --up -I 192.0.1.254 192.0.2.254
ipsec whack --trafficstatus
# cause cleartext failure
ip xfrm policy flush
# should cause failures on east
../../pluto/bin/ping-once.sh --down -I 192.0.1.254 192.0.2.254
echo done

# send one packet, which gets eaten by XFRM, so east does not initiate
../../pluto/bin/ping-once.sh --down -I 192.1.3.209 192.1.2.23 # should fail
# wait on OE to establish
../../pluto/bin/wait-for.sh --match private-or-clear -- ipsec whack --trafficstatus
# ping should succeed through tunnel
../../pluto/bin/ping-once.sh --up -I 192.1.3.209 192.1.2.23
ipsec whack --trafficstatus
echo done

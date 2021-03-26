# check traffic and shunt status - should be empty
ipsec whack --trafficstatus
ipsec whack --shuntstatus
# trigger ping, this will be lost
../../pluto/bin/ping-once.sh --down -I 192.1.3.209 192.1.2.23
# ping should succeed through tunnel
../../pluto/bin/ping-once.sh --up -I 192.1.3.209 192.1.2.23
ipsec whack --trafficstatus

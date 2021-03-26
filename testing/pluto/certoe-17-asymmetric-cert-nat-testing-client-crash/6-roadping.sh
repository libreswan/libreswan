# restart ipsec service
ipsec start
# give OE conns time to load
sleep 5
# trigger ping, this will be lost
../../pluto/bin/ping-once.sh --down -I 192.1.3.209 192.1.2.23
# ping should succeed through tunnel
../../pluto/bin/ping-once.sh --up -I 192.1.3.209 192.1.2.23
ipsec whack --trafficstatus

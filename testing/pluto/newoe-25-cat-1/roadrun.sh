# why more sleep?
sleep 5
ipsec whack --trafficstatus
ipsec whack --shuntstatus
../../pluto/bin/ipsec-look.sh
# trigger OE
../../pluto/bin/ping-once.sh --down -I 192.1.3.209 192.1.2.23
../../pluto/bin/wait-for.sh --match '"private-or-clear#192.1.2.0/24"' -- ipsec whack --trafficstatus
# ping should succeed through tunnel
../../pluto/bin/ping-once.sh --up -I 192.1.3.209 192.1.2.23
ipsec whack --trafficstatus
echo done

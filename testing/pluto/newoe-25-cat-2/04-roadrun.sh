ipsec whack --trafficstatus
ipsec whack --shuntstatus
../../pluto/bin/ipsec-look.sh
# bring up first tunnel
../../pluto/bin/ping-once.sh --down -I 192.1.3.209 192.1.2.23
../../pluto/bin/wait-for.sh --match '192.1.2.23' -- ipsec whack --trafficstatus
../../pluto/bin/ping-once.sh --up   -I 192.1.3.209 192.1.2.23
ipsec whack --trafficstatus
# bring up second tunnel
../../pluto/bin/ping-once.sh --down -I 192.1.3.209 192.1.2.45
../../pluto/bin/wait-for.sh --match '192.1.2.45' -- ipsec whack --trafficstatus
../../pluto/bin/ping-once.sh --up   -I 192.1.3.209 192.1.2.45
ipsec whack --trafficstatus
echo done

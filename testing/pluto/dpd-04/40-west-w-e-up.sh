# wait for west-east
../../guestbin/ping-once.sh --down -I 192.1.2.45 192.1.2.23
../../guestbin/wait-for.sh --match '"west-east"' -- ipsec whack --trafficstatus
../../guestbin/ping-once.sh --up -I 192.1.2.45 192.1.2.23

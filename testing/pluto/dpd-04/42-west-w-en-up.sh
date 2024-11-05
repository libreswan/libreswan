# wait for west-eastnet
../../guestbin/ping-once.sh --down -I 192.1.2.45 192.0.2.254
../../guestbin/wait-for.sh --match '"west-eastnet"' -- ipsec whack --trafficstatus
../../guestbin/ping-once.sh --up -I 192.1.2.45 192.0.2.254
../../guestbin/ping-once.sh --up -I 192.1.2.45 192.0.2.254

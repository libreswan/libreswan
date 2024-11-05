# wait for westnet-east
../../guestbin/ping-once.sh --down -I 192.0.1.254 192.1.2.23
../../guestbin/wait-for.sh --match '"westnet-east"' -- ipsec whack --trafficstatus
../../guestbin/ping-once.sh --up -I 192.0.1.254 192.1.2.23
../../guestbin/ping-once.sh --up -I 192.0.1.254 192.1.2.23
../../guestbin/ping-once.sh --up -I 192.0.1.254 192.1.2.23

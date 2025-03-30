../../guestbin/ping-once.sh --forget -I 192.0.1.254 192.0.2.254
../../guestbin/wait-for.sh --match westnet-eastnet-route -- ipsec whack --trafficstatus
../../guestbin/ping-once.sh --up -I 192.0.1.254 192.0.2.254
ipsec whack --trafficstatus
ipsec _kernel state
ipsec _kernel policy


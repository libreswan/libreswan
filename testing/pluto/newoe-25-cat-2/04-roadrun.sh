ipsec whack --trafficstatus
ipsec whack --shuntstatus
ipsec _kernel state
ipsec _kernel policy
# bring up first tunnel
../../guestbin/ping-once.sh --down -I 192.1.3.209 192.1.2.23
../../guestbin/wait-for.sh --match '192.1.2.23' -- ipsec whack --trafficstatus
../../guestbin/ping-once.sh --up   -I 192.1.3.209 192.1.2.23
ipsec whack --trafficstatus
# bring up second tunnel
../../guestbin/ping-once.sh --down -I 192.1.3.209 192.1.2.45
../../guestbin/wait-for.sh --match '192.1.2.45' -- ipsec whack --trafficstatus
../../guestbin/ping-once.sh --up   -I 192.1.3.209 192.1.2.45
ipsec whack --trafficstatus
echo done

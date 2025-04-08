ipsec whack --trafficstatus
ipsec whack --shuntstatus
ipsec _kernel state
ipsec _kernel policy
# ping should succeed through tunnel
../../guestbin/ping-once.sh --forget -I 192.1.3.209 192.1.2.23
../../guestbin/wait-for.sh --match 192.1.2.23 -- ipsec whack --trafficstatus
../../guestbin/ping-once.sh --up -I 192.1.3.209 192.1.2.23
# ping should succeed through tunnel
../../guestbin/ping-once.sh --forget -I 192.1.3.209 192.1.2.45
../../guestbin/wait-for.sh --match 192.1.2.45 -- ipsec whack --trafficstatus
../../guestbin/ping-once.sh --up -I 192.1.3.209 192.1.2.45
../../guestbin/ping-once.sh --up -I 192.1.3.209 192.1.2.45
# ping should succeed through tunnel
../../guestbin/ping-once.sh --forget -I 192.1.3.209 192.1.3.33
../../guestbin/wait-for.sh --match 192.1.3.33 -- ipsec whack --trafficstatus
../../guestbin/ping-once.sh --up -I 192.1.3.209 192.1.3.33
../../guestbin/ping-once.sh --up -I 192.1.3.209 192.1.3.33
../../guestbin/ping-once.sh --up -I 192.1.3.209 192.1.3.33
ipsec whack --trafficstatus
echo done

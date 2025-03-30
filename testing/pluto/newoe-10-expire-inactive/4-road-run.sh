# trigger OE
../../guestbin/ping-once.sh --forget -I 192.1.3.209 192.1.2.23
../../guestbin/wait-for.sh --match private-or-clear -- ipsec whack --trafficstatus
../../guestbin/ping-once.sh --up -I 192.1.3.209 192.1.2.23
ipsec whack --trafficstatus
ipsec whack --shuntstatus
# wait for IPSEC SA to expire due to inactivity; trafficstatus should
# be empty
../../guestbin/wait-for.sh --timeout 120 --no-match private-or-clear -- ipsec whack --trafficstatus
ipsec _kernel state
ipsec _kernel policy
#establish a new one
../../guestbin/ping-once.sh --forget -I 192.1.3.209 192.1.2.23
../../guestbin/wait-for.sh --match private-or-clear -- ipsec whack --trafficstatus
../../guestbin/ping-once.sh --up -I 192.1.3.209 192.1.2.23
ipsec whack --trafficstatus
ipsec _kernel state
ipsec _kernel policy
echo done

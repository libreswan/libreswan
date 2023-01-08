../../guestbin/wait-for.sh --match road/0x1 -- ipsec whack --trafficstatus
../../guestbin/wait-for.sh --match road/0x2 -- ipsec whack --trafficstatus
../../guestbin/ping-once.sh --up 192.0.2.254
../../guestbin/ping-once.sh --up 192.0.20.254
sleep 1
ipsec trafficstatus
echo done

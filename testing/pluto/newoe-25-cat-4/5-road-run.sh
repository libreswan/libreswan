ipsec whack --trafficstatus
ipsec whack --shuntstatus
../../guestbin/ipsec-look.sh
# ping should succeed through tunnel after triggering
../../guestbin/ping-once.sh --forget -I 192.1.3.209 192.1.2.23
../../guestbin/ping-once.sh --forget -I 192.1.3.209 192.1.2.45
../../guestbin/wait-for.sh --match 192.1.2.23 -- ipsec whack --trafficstatus
../../guestbin/wait-for.sh --match 10.0.10.1 -- ipsec whack --trafficstatus
../../guestbin/ping-once.sh --up -I 192.1.3.209 192.1.2.23
../../guestbin/ping-once.sh --up -I 192.1.3.209 192.1.2.45
# let the shunt drain
../../guestbin/wait-for.sh --no-match ' spi 0x00000000 ' -- ip xfrm state
echo done

# confirm received delete was processed - should show no tunnel
ipsec whack --trafficstatus
# let the old acquire expire so it won't interfere with our new trigger
../../guestbin/wait-for.sh --no-match ' spi 0x00000000 ' -- ipsec _kernel state
# try triggering again, ondemand policy should re-trigger OE
ipsec _kernel state
ipsec _kernel policy
../../guestbin/ping-once.sh --forget -I 192.1.2.45 192.1.2.23
../../guestbin/wait-for.sh --match private -- ipsec whack --trafficstatus
# wait on OE to re-establish IPsec SA
../../guestbin/wait-for.sh --no-match ' spi 0x00000000 ' -- ipsec _kernel state
../../guestbin/ping-once.sh --forget -I 192.1.2.45 192.1.2.23
ipsec _kernel state
ipsec _kernel policy
ipsec whack --shuntstatus
# ping should succeed through tunnel
../../guestbin/ping-once.sh --up -I 192.1.2.45 192.1.2.23
ipsec whack --trafficstatus

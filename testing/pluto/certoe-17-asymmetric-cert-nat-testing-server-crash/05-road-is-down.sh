# wait for DPD on road to trigger down
../../guestbin/wait-for.sh --no-match private-or-clear -- ipsec whack --trafficstatus

# failure=pass and negotiation=drop, what should be left?
../../guestbin/ipsec-kernel-policy.sh
ipsec whack --trafficstatus
ipsec whack --shuntstatus

# ping again to trigger OE. packet is lost
../../guestbin/ping-once.sh --forget -I 192.1.3.209 192.1.2.23
# check ping, expected to succeed now via %pass
../../guestbin/wait-for.sh --match %pass -- ipsec whack --shuntstatus
../../guestbin/ping-once.sh --up -I 192.1.3.209 192.1.2.23
# should show no tunnel
ipsec whack --trafficstatus
../../guestbin/ipsec-kernel-policy.sh

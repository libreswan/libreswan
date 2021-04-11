# check traffic status after east was crashed
# we expect the old tunnel and no shunts?
ipsec whack --trafficstatus
ipsec whack --shuntstatus
# wait for DPD on road to trigger down
../../guestbin/wait-for.sh --no-match private-or-clear -- ipsec whack --trafficstatus
# ping again to trigger OE. packet is lost
../../guestbin/ping-once.sh --forget -I 192.1.3.209 192.1.2.23
# check ping, expected to succeed now via %pass
../../guestbin/wait-for.sh --match %pass -- ipsec whack --shuntstatus
../../guestbin/ping-once.sh --up -I 192.1.3.209 192.1.2.23
# should show no tunnel
ipsec whack --trafficstatus

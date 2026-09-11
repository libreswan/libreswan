# IKE #1 CHILD #2
ipsec auto --up westnet-eastnet
../../guestbin/ping-once.sh --up -I 192.0.1.254 192.0.2.254
ipsec whack --trafficstatus
# no liveness probes sent yet
ipsec whack --globalstatus | grep total.ike.dpd
# trigger an on-demand liveness probe; whack blocks until the
# (empty INFORMATIONAL) response has been processed
ipsec whack --liveness --name westnet-eastnet
ipsec whack --globalstatus | grep total.ike.dpd
# tunnel still up
../../guestbin/ping-once.sh --up -I 192.0.1.254 192.0.2.254
ipsec whack --trafficstatus

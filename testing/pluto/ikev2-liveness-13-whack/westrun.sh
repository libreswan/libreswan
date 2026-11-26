# IKE #1 CHILD #2
ipsec up westnet-eastnet # sanitize-retransmits
../../guestbin/ping-once.sh --up -I 192.0.1.254 192.0.2.254
ipsec trafficstatus

# no liveness probes sent yet
ipsec globalstatus | grep total.ike.dpd

# trigger an on-demand liveness probe; whack blocks until the
# (empty INFORMATIONAL) response has been processed
ipsec whack --liveness --name westnet-eastnet
ipsec globalstatus | grep total.ike.dpd

# tunnel still up
../../guestbin/ping-once.sh --up -I 192.0.1.254 192.0.2.254
ipsec trafficstatus

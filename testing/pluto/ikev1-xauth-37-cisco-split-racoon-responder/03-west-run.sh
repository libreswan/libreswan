# create a partial state on east, don't hold the hack for retransmit
ipsec up west-east # sanitize-retransmits

ipsec _kernel state
ipsec _kernel policy

../../guestbin/ping-once.sh --up -I 192.0.2.101 192.0.2.254
ipsec trafficstatus
../../guestbin/ping-once.sh --up -I 192.0.2.101 192.0.20.254
ipsec trafficstatus

echo done

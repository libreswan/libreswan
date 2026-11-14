../../guestbin/ping-once.sh --up 192.1.2.23
ipsec up road-east-x509-ipv4
../../guestbin/ping-once.sh --up -I 192.0.2.100 192.1.2.23
# the narrowed selectors: our lease to anything
ipsec trafficstatus
ipsec _kernel policy | grep -E '^src'

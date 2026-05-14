ipsec up ikev2-westnet-eastnet-x509-cr # this should succeed # sanitize-retransmits
../../guestbin/ping-once.sh --up -I 192.0.1.254 192.0.2.254
ipsec trafficstatus
echo "done"

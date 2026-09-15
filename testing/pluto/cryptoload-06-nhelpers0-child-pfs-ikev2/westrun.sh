ipsec up westnet-eastnet-ikev2a # sanitize-retransmits
../../guestbin/ping-once.sh --up -I 192.0.1.254 192.0.2.254
ipsec up westnet-eastnet-ikev2b # sanitize-retransmits
../../guestbin/ping-once.sh --up -I 192.0.100.254 192.0.200.254
ipsec trafficstatus
echo done

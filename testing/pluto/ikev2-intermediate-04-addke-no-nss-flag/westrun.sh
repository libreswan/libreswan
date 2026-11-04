ipsec up west-mlkem # sanitize-retransmits
../../guestbin/ping-once.sh --up -I 192.0.1.254 192.0.2.254
ipsec trafficstatus
ipsec down west-mlkem

ipsec up west-ecp # sanitize-retransmits
../../guestbin/ping-once.sh --up -I 192.0.1.254 192.0.2.254
ipsec trafficstatus
ipsec down west-ecp

echo done

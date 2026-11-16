# IKE #1 CHILD #2

ipsec up west # sanitize-retransmits
../../guestbin/ping-once.sh --up -I 192.0.1.254 192.0.2.254
ipsec trafficstatus

# IKE #3 CHILD #2

ipsec whack --rekey-ike --name west # sanitize-retransmits
../../guestbin/ping-once.sh --up -I 192.0.1.254 192.0.2.254
ipsec trafficstatus
ipsec showstates

# IKE #4 CHILD #2

ipsec whack --rekey-ike --name west # sanitize-retransmits
../../guestbin/ping-once.sh --up -I 192.0.1.254 192.0.2.254
ipsec trafficstatus
ipsec showstates

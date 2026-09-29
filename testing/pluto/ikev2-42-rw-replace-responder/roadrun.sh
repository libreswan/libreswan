#!/bin/sh
../../guestbin/ping-once.sh --up 192.1.2.23
ipsec up road-east-x509-ipv4 # sanitize-retransmits
../../guestbin/ping-once.sh --up -I 192.0.2.100 192.1.2.23
ipsec trafficstatus

# wait for both rekey, ...
../../guestbin/wait-for-pluto.sh '^".*#3: responder rekeyed IKE SA #1'
# and delete, ...
../../guestbin/wait-for-pluto.sh '^".*#1: deleting'
# before trying ping (else ping races response)
../../guestbin/ping-once.sh --up -I 192.0.2.100 192.1.2.23
ipsec status
echo done

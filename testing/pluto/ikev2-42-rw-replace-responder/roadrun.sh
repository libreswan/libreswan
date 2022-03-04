#!/bin/sh
../../guestbin/ping-once.sh --up 192.1.2.23
ipsec auto --up road-east-x509-ipv4
../../guestbin/ping-once.sh --up -I 192.0.2.100 192.1.2.23
ipsec whack --trafficstatus
# east's rekey is 50s, margin 10s
sleep 40
# wait for both rekey, ...
../../guestbin/wait-for.sh --match '#3: responder rekeyed IKE SA #1' -- cat /tmp/pluto.log
# and delete, ...
../../guestbin/wait-for.sh --match '#1: deleting' -- cat /tmp/pluto.log
# before trying ping (else ping races response)
../../guestbin/ping-once.sh --up -I 192.0.2.100 192.1.2.23
ipsec status
echo done

ipsec up west # sanitize-retransmits
../../guestbin/ping-once.sh --up -I 192.0.1.254 192.0.2.254
ipsec trafficstatus
ipsec showstates

../../guestbin/wait-for-pluto.sh --match '#3: initiator rekeyed Child SA #2 using #1'
../../guestbin/ping-once.sh --up -I 192.0.1.254 192.0.2.254
../../guestbin/wait-for-pluto.sh --match '#2: ESP traffic information'
ipsec trafficstatus
ipsec showstates

../../guestbin/wait-for-pluto.sh --match '#4: initiator rekeyed IKE SA #1'
../../guestbin/ping-once.sh --up -I 192.0.1.254 192.0.2.254
../../guestbin/wait-for-pluto.sh --match '#1: deleting IKE SA'
# we're a bit agressive ...
../../guestbin/wait-for-pluto.sh --match 'INFORMATIONAL response has no corresponding IKE SA'
ipsec trafficstatus
ipsec showstates

../../guestbin/wait-for-pluto.sh --match '#5: initiator rekeyed Child SA #3 using #4'
../../guestbin/ping-once.sh --up -I 192.0.1.254 192.0.2.254
../../guestbin/wait-for-pluto.sh --match '#3: ESP traffic information'
ipsec trafficstatus
ipsec showstates

echo done

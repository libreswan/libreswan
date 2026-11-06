ipsec up west-cuckold # sanitize-retransmits
ipsec up west-cuckoo  # sanitize-retransmits

ipsec whack --rekey-ike --name west-cuckold --asynchronous

../../guestbin/wait-for-pluto.sh '#4: initiator rekeyed IKE SA #1'

../../guestbin/ping-once.sh --up 192.0.2.254
../../guestbin/ping-once.sh --up 192.0.20.254
ipsec trafficstatus

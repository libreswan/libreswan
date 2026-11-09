ipsec up west-cuckold # sanitize-retransmits
ipsec up west-cuckoo  # sanitize-retransmits

../../guestbin/ping-once.sh --up 192.0.2.254
../../guestbin/ping-once.sh --up 192.0.20.254
ipsec trafficstatus

# CREATE_CHILD_SA followed by three IKE_FOLLOWUP_KE exchanges
ipsec whack --rekey-child --name west-cuckoo # sanitize-retransmits
ipsec whack --rekey-child --name west-cuckold # sanitize-retransmits

../../guestbin/ping-once.sh --up 192.0.2.254
../../guestbin/ping-once.sh --up 192.0.20.254
ipsec trafficstatus

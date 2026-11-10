# IKE_AUTH; Child SA uses the IKE SA's keys, no IKE_FOLLOWUP_KE
ipsec up west-cuckold # sanitize-retransmits
# CREATE_CHILD_SA followed by two IKE_FOLLOWUP_KE exchanges
ipsec up west-cuckoo  # sanitize-retransmits

../../guestbin/ping-once.sh --up 192.0.2.254
../../guestbin/ping-once.sh --up 192.0.20.254
ipsec trafficstatus

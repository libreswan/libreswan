# bring up server behind NAT "road"
ipsec add road-east
ipsec up road-east # sanitize-retransmits
ipsec trafficstatus

# We simulate two behind nat by simply deleting first connection
# without sending deletes on road.
ipsec whack --impair send_no_delete
ipsec delete road-east # never retransmits

# Second connection
ipsec add runner-east
ipsec up runner-east # sanitize-retransmits

echo done

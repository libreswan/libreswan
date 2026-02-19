ipsec whack --impair revival

# establish the IKE SA, and first connection

ipsec up west-cuckoo # sanitize-retransmits
ipsec whack --impair trigger_revival:1 # sanitize-retransmits

# initiate the second connection; will create its own IKE SA and then
# fail as east isn't set up to accept it (and it doesn't allow redirect)
ipsec up west-cuckold # sanitize-retransmits

ipsec trafficstatus

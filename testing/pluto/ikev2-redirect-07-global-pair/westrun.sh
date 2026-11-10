ipsec whack --impair revival

# establish the IKE SA, and first connection

ipsec up west-cuckoo # sanitize-retransmits
ipsec whack --impair trigger_revival:1 # sanitize-retransmits

# initiate the second connection; will create its own IKE SA and then
# redirect.
ipsec up west-cuckold # sanitize-retransmits
# re-initiate the second connection; it will now match the first IKE
# SA and use it.
ipsec whack --impair trigger_revival:2 # sanitize-retransmits

ipsec trafficstatus

ipsec whack --impair revival

# establish the IKE SA, and first connection

ipsec auto --up west-cuckoo
ipsec whack --impair trigger-revival:1

# initiate the second connection; will create its own IKE SA and then
# fail as east isn't set up to accept it (and it doesn't allow redirect)
ipsec auto --up west-cuckold

ipsec trafficstatus

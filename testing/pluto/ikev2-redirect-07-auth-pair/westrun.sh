ipsec whack --impair revival

# establish the IKE SA, and first connection

ipsec auto --up west-cuckoo
ipsec whack --impair trigger-revival:1

# initiate the second connection; will create its own IKE SA and then
# redirect.
ipsec auto --up west-cuckold
# re-initiate the second connection; it will now match the first IKE
# SA and use it.
ipsec whack --impair trigger-revival:2

ipsec trafficstatus

ipsec whack --impair suppress-retransmits
# should fail to establish
ipsec auto --up  westnet-eastnet-ikev2
echo done

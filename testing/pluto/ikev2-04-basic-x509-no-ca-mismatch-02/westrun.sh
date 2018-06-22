# we are expecting to fail
ipsec whack --impair suppress-retransmits
ipsec auto --up  westnet-eastnet-ikev2
echo done

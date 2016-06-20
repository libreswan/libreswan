ipsec whack --debug-all --impair-retransmits
# should fail to establish
ipsec auto --up  westnet-eastnet-ikev2
echo done

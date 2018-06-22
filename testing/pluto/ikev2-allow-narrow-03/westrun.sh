ipsec whack --impair retransmits
# should fail to establish
ipsec auto --up  westnet-eastnet-ikev2
echo done

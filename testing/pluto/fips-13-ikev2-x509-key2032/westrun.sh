ipsec whack --impair suppress_retransmits
# should fail - our FIPS code requires 3072 minimum key
ipsec auto --up westnet-eastnet-ikev2
echo done

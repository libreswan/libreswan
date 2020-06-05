ipsec whack --impair delete-on-retransmit
# should fail - our FIPS code requires 2048 minimum key
ipsec auto --up westnet-eastnet-ikev2
echo done

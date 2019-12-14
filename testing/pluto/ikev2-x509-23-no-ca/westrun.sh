ipsec whack --impair delete-on-retransmit
# this should fail
ipsec auto --up ikev2-westnet-eastnet-x509-cr
echo "done"

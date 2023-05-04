ipsec whack --impair timeout-on-retransmit
ipsec whack --impair revival
# this should fail
ipsec auto --up ikev2-westnet-eastnet-x509-cr
echo "done"

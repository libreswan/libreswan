ipsec whack --impair suppress_retransmits
# this should fail
ipsec auto --up ikev2-westnet-eastnet-x509-cr
echo "done"

ipsec whack --impair suppress-retransmits
ipsec whack --impair revival
# this should succeed
ipsec auto --up san
echo "done"

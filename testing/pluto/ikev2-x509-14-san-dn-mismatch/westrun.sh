ipsec whack --impair suppress_retransmits
ipsec whack --impair revival
# this should succeed
ipsec auto --up san
echo "done"

ipsec whack --impair suppress_retransmits
ipsec whack --impair revival
# this should fail
ipsec auto --up san
echo "done"

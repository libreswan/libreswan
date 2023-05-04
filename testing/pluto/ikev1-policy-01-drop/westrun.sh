ipsec whack --impair timeout-on-retransmit --impair revival
# should fail
ipsec auto --up ikev1
echo done

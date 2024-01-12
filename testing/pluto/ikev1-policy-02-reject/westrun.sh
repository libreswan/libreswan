ipsec whack --impair timeout_on_retransmit --impair revival
# should fail
ipsec auto --up ikev1
echo done

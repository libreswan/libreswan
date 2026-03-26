ipsec whack --impair timeout_on_retransmit --impair revival
# should fail
ipsec auto --up ikev1
# should work normal
ipsec auto --up ikev2
# should mangle
ipsec whack --impair major_version_bump
ipsec auto --up ikev2
echo done

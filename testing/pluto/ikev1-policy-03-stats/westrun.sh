ipsec whack --impair revival
# should fail
ipsec up ikev1 # suppress-retransmits
# should work normal
ipsec up ikev2 # suppress-retransmits
# should mangle
ipsec whack --impair major_version_bump
ipsec up ikev2
echo done

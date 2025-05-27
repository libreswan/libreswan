ipsec whack --impair suppress_retransmits

# this should succeed
ipsec up san-openssl
ipsec down san-openssl

# this should succeed
ipsec up san-nss
ipsec down san-nss

echo "done"

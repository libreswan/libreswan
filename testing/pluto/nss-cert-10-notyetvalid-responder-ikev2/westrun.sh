ipsec whack --impair suppress-retransmits
ipsec whack --impair revival
# This is expected to fail because remote cert is not yet valid.
ipsec auto --up nss-cert
echo done

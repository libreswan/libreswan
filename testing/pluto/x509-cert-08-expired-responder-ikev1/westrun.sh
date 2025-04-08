ipsec whack --impair suppress_retransmits
ipsec whack --impair revival
# This is expected to fail because remote cert is not yet valid.
ipsec auto --up west
echo done


 ipsec whack --impair timeout_on_retransmit
ipsec whack --impair revival
# This is expected to fail because remote cert is not yet valid.
ipsec auto --up nss-cert
echo done

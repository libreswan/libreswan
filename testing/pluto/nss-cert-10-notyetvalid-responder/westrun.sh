ipsec whack --impair delete-on-retransmit
# This is expected to fail because remote cert is not yet valid.
# It should return whack but it does not?
ipsec auto --up nss-cert
echo done

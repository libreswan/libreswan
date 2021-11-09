# this is expected to fail to due the BAD CA that has no CA:TRUE Basic Constraint set
ipsec whack --impair delete-on-retransmit
ipsec whack --impair revival
ipsec auto --up nss-cert
echo done

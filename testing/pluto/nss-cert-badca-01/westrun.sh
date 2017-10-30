# this is expected to fail to due the BAD CA that has no CA:TRUE Basic Constraint set
ipsec whack --debug-all --impair retransmits
ipsec auto --up nss-cert
echo done

# the impair causes memory corruption and a crash ?
ipsec whack --debug-all --impair retransmits
# should succeed
ipsec auto --up nss-cert-correct
ipsec auto --down nss-cert-correct
# should fail on mismatched ID
ipsec auto --up nss-cert-incorrect
echo done

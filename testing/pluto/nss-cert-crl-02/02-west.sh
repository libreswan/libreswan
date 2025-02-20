/testing/guestbin/swan-prep --nokeys

/testing/x509/import.sh real/mainca/revoked.all.p12
ipsec certutil -L

ipsec start
../../guestbin/wait-until-pluto-started
ipsec whack --impair timeout_on_retransmit
ipsec auto --add nss-cert-crl
ipsec auto --status |grep nss-cert-crl
echo "initdone"
ipsec auto --up nss-cert-crl
echo done

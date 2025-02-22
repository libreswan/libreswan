/testing/guestbin/swan-prep --nokeys

/testing/x509/import.sh real/mainca/`hostname`.all.p12

/testing/x509/import.sh real/mainca/revoked.all.p12
ipsec certutil -L

ipsec start
../../guestbin/wait-until-pluto-started
ipsec whack --impair suppress_retransmits
ipsec whack --impair revival
ipsec auto --add nss-cert-ocsp
ipsec auto --status |grep nss-cert-ocsp
echo "initdone"
ipsec auto --up nss-cert-ocsp
echo done

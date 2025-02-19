/testing/guestbin/swan-prep --nokeys

/testing/x509/import.sh real/mainca/east.all.p12
/testing/x509/import.sh real/mainca/crl-is-out-of-date.crl

ipsec start
../../guestbin/wait-until-pluto-started
ipsec auto --add nss-cert-crl
ipsec auto --status |grep nss-cert-crl
echo "initdone"

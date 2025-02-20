/testing/guestbin/swan-prep --nokeys

/testing/x509/import.sh real/mainca/west.all.p12

ipsec start
../../guestbin/wait-until-pluto-started
ipsec auto --add nss-cert-crl
ipsec auto --status |grep nss-cert-crl
echo "initdone"
ipsec auto --up nss-cert-crl
echo done

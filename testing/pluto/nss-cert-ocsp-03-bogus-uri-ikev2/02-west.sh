/testing/guestbin/swan-prep --nokeys

/testing/x509/import.sh real/mainca/`hostname`.p12

ipsec start
../../guestbin/wait-until-pluto-started
ipsec add nss-cert-ocsp
ipsec connectionstatus nss-cert-ocsp
echo "initdone"
ipsec up nss-cert-ocsp # sanitize-retransmits
echo done

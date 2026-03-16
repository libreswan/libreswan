/testing/guestbin/swan-prep --nokeys

/testing/x509/import.sh real/mainca/`hostname`.p12

ipsec start
../../guestbin/wait-until-pluto-started
ipsec add nss-cert
echo "initdone"
ipsec up nss-cert # sanitize-retransmits
echo done

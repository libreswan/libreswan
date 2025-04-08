/testing/guestbin/swan-prep --nokeys

/testing/x509/import.sh real/mainca/east.p12
/testing/x509/import.sh otherca/root.cert
# check
ipsec certutil -L

ipsec start
../../guestbin/wait-until-pluto-started
ipsec auto --add nss-cert-correct
ipsec auto --add nss-cert-wrong
ipsec auto --status |grep nss-cert
echo "initdone"

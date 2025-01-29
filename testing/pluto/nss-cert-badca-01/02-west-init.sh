/testing/guestbin/swan-prep --nokeys

/testing/x509/import.sh real/mainca/root.cert
/testing/x509/import.sh real/badca/badwest.all.p12

# check
ipsec certutil -L

ipsec start
../../guestbin/wait-until-pluto-started
ipsec auto --add nss-cert
ipsec auto --status |grep nss-cert
echo "initdone"

/testing/guestbin/swan-prep --nokeys

# pull in the full east
/testing/x509/import.sh real/mainca/east.all.p12

/testing/x509/import.sh real/badca/badeast.all.p12
# check
ipsec certutil -L

ipsec start
../../guestbin/wait-until-pluto-started
ipsec auto --add nss-cert
ipsec auto --status |grep nss-cert
echo "initdone"

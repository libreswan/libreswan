/testing/guestbin/swan-prep --nokeys

/testing/x509/import.sh real/mainca/`hostname`.all.p12
/testing/x509/import.sh real/bc-n-ca/bc-n-ca.all.p12

ipsec start
../../guestbin/wait-until-pluto-started
ipsec add east
echo "initdone"

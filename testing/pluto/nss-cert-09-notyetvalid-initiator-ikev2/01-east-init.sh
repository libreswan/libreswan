/testing/guestbin/swan-prep --nokeys

/testing/x509/import.sh real/mainca/east.all.p12

ipsec start
../../guestbin/wait-until-pluto-started
ipsec auto --add nss-cert
echo "initdone"

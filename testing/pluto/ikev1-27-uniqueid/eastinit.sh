/testing/guestbin/swan-prep --nokeys
/testing/x509/import.sh real/mainca/east.p12
/testing/x509/import.sh real/mainca/north.end.cert
ipsec start
../../guestbin/wait-until-pluto-started
ipsec auto --add road-eastnet-ikev2
echo "initdone"

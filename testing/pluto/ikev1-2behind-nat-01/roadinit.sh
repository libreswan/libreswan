/testing/guestbin/swan-prep --nokeys
/testing/x509/import.sh real/mainca/road.p12
/testing/x509/import.sh real/mainca/east.end.cert
/testing/x509/import.sh real/mainca/north.p12
ipsec start
../../guestbin/wait-until-pluto-started
ipsec auto --add road
echo "initdone"

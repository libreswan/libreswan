/testing/guestbin/swan-prep --nokeys
/testing/x509/import.sh real/mainca/east.p12
/testing/x509/import.sh real/mainca/road.end.cert
/testing/x509/import.sh real/mainca/north.end.cert
ipsec start
../../guestbin/wait-until-pluto-started
ipsec add any-east # alias
echo initdone

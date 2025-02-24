/testing/guestbin/swan-prep --x509
/testing/x509/import.sh real/mainca/north.all.p12
ipsec start
../../guestbin/wait-until-pluto-started
ipsec auto --add road
echo "initdone"

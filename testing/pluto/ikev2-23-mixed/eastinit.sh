/testing/guestbin/swan-prep --nokeys
/testing/x509/import.sh real/mainca/east.p12
/testing/x509/import.sh real/mainca/road.end.cert
ipsec start
../../guestbin/wait-until-pluto-started
ipsec auto --add road-east-ipv4-ikev2
ipsec auto --add road-east-ipv4
echo "initdone"

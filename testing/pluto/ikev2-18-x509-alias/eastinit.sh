/testing/guestbin/swan-prep --46 --nokeys
/testing/x509/import.sh real/mainca/east.p12
/testing/x509/import.sh real/mainca/road.end.cert
ipsec start
../../guestbin/wait-until-pluto-started
ipsec auto --add road-east-ipv4-psk-ikev2
ipsec auto --add road-east-ipv6-psk-ikev2
ipsec auto --status | grep road-east
echo "initdone"

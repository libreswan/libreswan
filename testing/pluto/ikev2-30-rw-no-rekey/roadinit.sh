/testing/guestbin/swan-prep --nokeys
/testing/x509/import.sh real/mainca/road.p12
/testing/x509/import.sh real/mainca/east.end.cert
ipsec start
../../guestbin/wait-until-pluto-started
ipsec auto --add road-east-x509-ipv4
ipsec whack --impair suppress_retransmits
ipsec whack --impair revival
echo "initdone"

/testing/guestbin/swan-prep --nokeys
/testing/x509/import.sh real/mainca/north.p12
/testing/x509/import.sh real/mainca/east.end.cert
ipsec start
../../guestbin/wait-until-pluto-started
ipsec auto --add northnet-eastnet-nat
ipsec whack --impair suppress_retransmits
echo "initdone"

/testing/guestbin/swan-prep --nokeys
# no CA, no peer cert
/testing/x509/import.sh real/mainca/east.end.p12

ipsec start
../../guestbin/wait-until-pluto-started
ipsec auto --add ikev2-westnet-eastnet-x509-cr
echo "initdone"

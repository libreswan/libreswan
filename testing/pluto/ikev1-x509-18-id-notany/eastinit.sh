/testing/guestbin/swan-prep --nokeys
/testing/x509/import.sh real/mainca/east-nosan.p12
ipsec start
../../guestbin/wait-until-pluto-started
ipsec auto --add ikev2-westnet-eastnet-x509-cr
ipsec status | grep idtype
echo "initdone"

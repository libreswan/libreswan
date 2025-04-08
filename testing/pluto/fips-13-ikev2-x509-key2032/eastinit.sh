/testing/guestbin/swan-prep --nokeys --fips

/testing/x509/import.sh real/mainca/east.p12

ipsec start
../../guestbin/wait-until-pluto-started
ipsec add westnet-eastnet-ikev2
echo "initdone"

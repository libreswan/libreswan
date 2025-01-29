/testing/guestbin/swan-prep --nokeys

# oops! WEST is loading up NORTH
/testing/x509/import.sh real/mainca/north.all.p12
/testing/x509/import.sh real/mainca/east.end.cert
ipsec certutil -L

ipsec start
../../guestbin/wait-until-pluto-started
ipsec auto --add westnet-eastnet-ikev2
ipsec auto --status | grep westnet-eastnet-ikev2
echo "initdone"

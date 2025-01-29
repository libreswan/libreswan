/testing/guestbin/swan-prep --nokeys

# east needs it's identity
/testing/x509/import.sh real/mainca/east.all.p12

ipsec start
../../guestbin/wait-until-pluto-started
ipsec auto --add westnet-eastnet-ikev2
ipsec auto --status | grep westnet-eastnet-ikev2
echo "initdone"

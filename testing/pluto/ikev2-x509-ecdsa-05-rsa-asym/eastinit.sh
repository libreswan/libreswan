/testing/guestbin/swan-prep --nokeys
/testing/x509/import.sh real/mainec/`hostname`.p12
/testing/x509/import.sh real/mainca/mainca.p12

ipsec start
../../guestbin/wait-until-pluto-started
ipsec auto --add westnet-eastnet-ikev2
echo "initdone"

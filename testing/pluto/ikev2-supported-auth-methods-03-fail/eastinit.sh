/testing/guestbin/swan-prep --x509
/testing/x509/import.sh real/mainca/rsa-`hostname`.p12
/testing/x509/import.sh real/mainec/ecdsa-`hostname`.p12

ipsec start
../../guestbin/wait-until-pluto-started

ipsec auto --add westnet-eastnet-ikev2
echo "initdone"

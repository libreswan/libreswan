/testing/guestbin/swan-prep --nokeys
/testing/x509/import.sh real/mainca/east.p12
/testing/x509/import.sh real/mainca/west.end.cert
ipsec start
../../guestbin/wait-until-pluto-started
ipsec auto --add ikev2-westnet-eastnet-x509-cr
ipsec whack --impair send_pkcs7_thingie
echo "initdone"

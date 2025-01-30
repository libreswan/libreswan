/testing/guestbin/swan-prep --nokeys
/testing/x509/import.sh real/mainca/east.end.p12
/testing/x509/import.sh real/mainca/west.end.cert

ipsec start
../../guestbin/wait-until-pluto-started
ipsec whack --impair send_pkcs7_thingie
ipsec auto --add westnet-eastnet-x509
ipsec auto --status | grep westnet-eastnet-x509
echo "initdone"

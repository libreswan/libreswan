/testing/guestbin/swan-prep --nokeys
/testing/x509/import.sh real/mainca/east.p12

ipsec start
../../guestbin/wait-until-pluto-started
ipsec add ikev2-westnet-eastnet-x509-cr
ipsec whack --impair send_pkcs7_thingie:1 # CERTS
echo "initdone"

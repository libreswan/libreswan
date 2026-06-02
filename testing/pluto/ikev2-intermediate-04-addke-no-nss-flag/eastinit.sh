/testing/guestbin/swan-prep --nokeys
ipsec modutil -undefault 'NSS Internal PKCS #11 Module' -mechanisms ECC </dev/null
/testing/x509/import.sh real/mainca/east.p12

ipsec start
../../guestbin/wait-until-pluto-started

ipsec auto --add east

echo "initdone"

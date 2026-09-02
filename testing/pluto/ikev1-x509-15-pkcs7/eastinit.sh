/testing/guestbin/swan-prep --nokeys
/testing/x509/import.sh real/mainca/east.p12

ipsec start
../../guestbin/wait-until-pluto-started
ipsec whack --impair send_pkcs7_thingie:1 # CERTS
ipsec add westnet-eastnet-x509
ipsec connectionstatus westnet-eastnet-x509
echo "initdone"

/testing/guestbin/swan-prep --x509
ipsec certutil -D -n east
ipsec start
../../guestbin/wait-until-pluto-started

ipsec add san-openssl
ipsec add san-nss

echo "initdone"

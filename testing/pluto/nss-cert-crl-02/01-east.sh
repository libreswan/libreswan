/testing/guestbin/swan-prep --x509
ipsec crlutil -I -i /testing/x509/crls/cacrlvalid.crl
ipsec certutil -D -n west
ipsec certutil -L

ipsec start
../../guestbin/wait-until-pluto-started
ipsec auto --add nss-cert-crl
ipsec auto --status |grep nss-cert-crl
echo "initdone"

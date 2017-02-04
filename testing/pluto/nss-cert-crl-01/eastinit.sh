/testing/guestbin/swan-prep --x509
crlutil -I -i /testing/x509/crls/cacrlvalid.crl -d sql:/etc/ipsec.d
certutil -d sql:/etc/ipsec.d -D -n west
ipsec start
/testing/pluto/bin/wait-until-pluto-started
ipsec auto --add nss-cert-crl
ipsec auto --status |grep nss-cert-crl
echo "initdone"

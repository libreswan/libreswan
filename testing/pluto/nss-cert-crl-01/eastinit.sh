/testing/guestbin/swan-prep --x509
cp /testing/x509/crls/cacrlvalid.crl /etc/ipsec.d/crls
certutil -d sql:/etc/ipsec.d -D -n west
ipsec start
/testing/pluto/bin/wait-until-pluto-started
ipsec auto --add nss-cert-crl
ipsec auto --status |grep nss-cert-crl
echo "initdone"

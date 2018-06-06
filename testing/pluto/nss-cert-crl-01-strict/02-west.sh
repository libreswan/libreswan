/testing/guestbin/swan-prep --x509
certutil -d sql:/etc/ipsec.d -D -n east
ipsec start
/testing/pluto/bin/wait-until-pluto-started
ipsec auto --add nss-cert-crl
ipsec auto --status |grep nss-cert-crl
echo "initdone"
ipsec auto --up nss-cert-crl
echo done

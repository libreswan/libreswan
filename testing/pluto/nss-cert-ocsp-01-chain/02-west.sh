/testing/guestbin/swan-prep --x509 --certchain
ipsec start
/testing/pluto/bin/wait-until-pluto-started
ipsec auto --add nss-cert-ocsp
ipsec auto --status |grep nss-cert-ocsp
echo "initdone"
ipsec auto --up nss-cert-ocsp
echo done

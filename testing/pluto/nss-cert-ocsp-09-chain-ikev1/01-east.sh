/testing/guestbin/swan-prep --x509 --certchain

ipsec certutil -D -n nic
/testing/x509/import.sh real/mainca/nic.end.cert

ipsec start
../../guestbin/wait-until-pluto-started
ipsec auto --add nss-cert-ocsp
ipsec auto --status |grep nss-cert-ocsp
echo "initdone"

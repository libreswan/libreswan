/testing/guestbin/swan-prep --x509 --certchain
ipsec start
/testing/pluto/bin/wait-until-pluto-started
ipsec auto --add nss-cert-chain
ipsec auto --status |grep nss-cert-chain
echo "initdone"

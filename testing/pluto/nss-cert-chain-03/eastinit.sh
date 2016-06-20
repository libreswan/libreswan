/testing/guestbin/swan-prep --x509 --certchain
certutil -A -d sql:/etc/ipsec.d/ -i /testing/x509/certs/west_chain_int_1.crt -t ",," -n "west_chain_int_1"
ipsec start
/testing/pluto/bin/wait-until-pluto-started
ipsec auto --add nss-cert-chain
ipsec auto --status |grep nss-cert-chain
echo "initdone"

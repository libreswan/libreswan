/testing/guestbin/swan-prep --x509 --certchain
ipsec certutil -A -i /testing/x509/certs/east_chain_int_1.crt -t ",," -n "east_chain_int_1"
ipsec start
../../guestbin/wait-until-pluto-started
ipsec auto --add nss-cert-chain
ipsec auto --status |grep nss-cert-chain
ipsec whack --impair suppress_retransmits
echo "initdone"

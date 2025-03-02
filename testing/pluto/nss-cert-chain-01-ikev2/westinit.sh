/testing/guestbin/swan-prep --nokeys

/testing/x509/import.sh real/mainca/west_chain_endcert.all.p12

ipsec start
../../guestbin/wait-until-pluto-started
ipsec auto --add nss-cert-chain
ipsec auto --status |grep nss-cert-chain
ipsec whack --impair suppress_retransmits
echo "initdone"

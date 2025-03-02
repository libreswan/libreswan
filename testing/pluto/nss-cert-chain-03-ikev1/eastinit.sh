/testing/guestbin/swan-prep --nokeys

# what we send to peer
/testing/x509/import.sh real/mainca/east_chain_endcert.end.p12
/testing/x509/import.sh real/mainca/east_chain_int_2.end.cert

# how we authenticate peer
/testing/x509/import.sh real/mainca/west_chain_int_1.end.cert
/testing/x509/import.sh real/mainca/root.cert

ipsec start
../../guestbin/wait-until-pluto-started
ipsec auto --add nss-cert-chain
ipsec auto --status |grep nss-cert-chain
ipsec whack --impair suppress_retransmits
echo "initdone"

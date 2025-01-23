/testing/guestbin/swan-prep --x509 --certchain
ipsec pk12util -i /testing/x509/pkcs12/west_chain_endcert.p12 -W "foobar"
ipsec certutil -A -i /testing/x509/certs/west_chain_int_1.crt -n "east_chain_1" -t "CT,,"
ipsec certutil -A -i /testing/x509/certs/west_chain_int_2.crt -n "east_chain_2" -t "CT,,"
# check
ipsec certutil -L

ipsec start
../../guestbin/wait-until-pluto-started
ipsec auto --add road-chain-B
ipsec auto --status |grep road-chain-B
ipsec certutil -L
ipsec whack --impair suppress_retransmits
echo "initdone"

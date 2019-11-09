/testing/guestbin/swan-prep --x509 --certchain
pk12util -i /testing/x509/pkcs12/west_chain_endcert.p12 -d sql:/etc/ipsec.d -W "foobar"
certutil -A -i /testing/x509/certs/west_chain_int_1.crt -n "east_chain_1" -d sql:/etc/ipsec.d -t "CT,,"
certutil -A -i /testing/x509/certs/west_chain_int_2.crt -n "east_chain_2" -d sql:/etc/ipsec.d -t "CT,,"
ipsec start
/testing/pluto/bin/wait-until-pluto-started
ipsec auto --add road-chain-B
ipsec auto --status |grep road-chain-B
certutil -L -d sql:/etc/ipsec.d
ipsec whack --impair suppress-retransmits
echo "initdone"

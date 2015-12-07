/testing/guestbin/swan-prep --x509 --certchain
pk12util -i /testing/x509/pkcs12/mainca/west.p12 -d sql:/etc/ipsec.d -W "foobar"
certutil -A -i /testing/x509/certs/east_chain_int_1.crt -n "east_chain_1" -d sql:/etc/ipsec.d -t "CT,,"
certutil -A -i /testing/x509/certs/east_chain_int_2.crt -n "east_chain_2" -d sql:/etc/ipsec.d -t "CT,,"
ipsec setup start
/testing/pluto/bin/wait-until-pluto-started
ipsec auto --add chain-A
ipsec auto --add chain-B
ipsec auto --status |grep chain
certutil -L -d sql:/etc/ipsec.d
echo "initdone"

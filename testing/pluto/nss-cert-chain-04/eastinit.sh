/testing/guestbin/swan-prep --x509 --certchain
certutil -A -i /testing/x509/certs/west_chain_int_1.crt -n "west_chain_1" -d sql:/etc/ipsec.d -t "CT,,"
certutil -A -i /testing/x509/certs/west_chain_int_2.crt -n "west_chain_2" -d sql:/etc/ipsec.d -t "CT,,"
ipsec setup start
/testing/pluto/bin/wait-until-pluto-started
ipsec auto --add chain-A
ipsec auto --add chain-B
ipsec auto --status |grep chain
certutil -L -d sql:/etc/ipsec.d
echo "initdone"

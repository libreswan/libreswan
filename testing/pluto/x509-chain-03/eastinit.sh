/testing/guestbin/swan-prep --x509 --certchain
certutil -A -n "west_chain_intermediate_2" -d sql:/etc/ipsec.d -t 'c,,' -a -i /testing/x509/cacerts/west_chain_intermediate_2.crt
certutil -A -n "west_chain_intermediate_1" -d sql:/etc/ipsec.d -t 'c,,' -a -i /testing/x509/cacerts/west_chain_intermediate_1.crt
ipsec setup start
/testing/pluto/bin/wait-until-pluto-started
ipsec auto --add westnet-eastnet-x509-chain
echo "initdone"

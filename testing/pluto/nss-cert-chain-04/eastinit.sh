/testing/guestbin/swan-prep --x509
# east MUST NOT have intermediate ceritificates available - they are changing target like end target
#certutil -A -i /testing/x509/certs/west_chain_int_1.crt -n "west_chain_1" -d sql:/etc/ipsec.d -t "CT,,"
#certutil -A -i /testing/x509/certs/west_chain_int_2.crt -n "west_chain_2" -d sql:/etc/ipsec.d -t "CT,,"
certutil -A -i /testing/x509/cacerts/otherca.crt -n "otherca" -d sql:/etc/ipsec.d -t "CT,,"
ipsec start
/testing/pluto/bin/wait-until-pluto-started
ipsec auto --add road-chain-B
ipsec auto --add road-A
ipsec auto --status |grep road
certutil -L -d sql:/etc/ipsec.d
echo "initdone"

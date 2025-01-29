/testing/guestbin/swan-prep --x509
# east MUST NOT have intermediate ceritificates available - they are changing target like end target
#ipsec certutil -A -i /testing/x509/certs/west_chain_int_1.crt -n "west_chain_1" -t "CT,,"
#ipsec certutil -A -i /testing/x509/certs/west_chain_int_2.crt -n "west_chain_2" -t "CT,,"
/testing/x509/import.sh real/otherca/root.cert
# check
ipsec certutil -L

ipsec start
../../guestbin/wait-until-pluto-started
ipsec auto --add road-chain-B
ipsec auto --add road-A
ipsec auto --status |grep road
ipsec certutil -L
echo "initdone"

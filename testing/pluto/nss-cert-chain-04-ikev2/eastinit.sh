/testing/guestbin/swan-prep --x509
ipsec pk12util -i /testing/x509/pkcs12/east.p12 -W "foobar"
# east MUST NOT have intermediate ceritificates available - they are changing target like end target
#ipsec certutil -A -i /testing/x509/certs/west_chain_int_1.crt -n "west_chain_1" -t "CT,,"
#ipsec certutil -A -i /testing/x509/certs/west_chain_int_2.crt -n "west_chain_2" -t "CT,,"
ipsec certutil -A -i /testing/x509/cacerts/otherca.crt -n "otherca" -t "CT,,"
ipsec start
../../guestbin/wait-until-pluto-started
../../guestbin/ipsec-add.sh road-A road-chain-B
ipsec status | sed -n -e '/road/ { s/conn serial: [^;]*;/conn serial: .../; p; }'
ipsec certutil -L
echo "initdone"

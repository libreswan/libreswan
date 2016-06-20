/testing/guestbin/swan-prep --x509
certutil -D -n east -d sql:/etc/ipsec.d
certutil -D -n east-ec -d sql:/etc/ipsec.d
ipsec import /testing/x509/pkcs12/otherca/signedbyother.p12
ipsec start
/testing/pluto/bin/wait-until-pluto-started
ipsec whack --debug-all --impair-retransmits
ipsec auto --add westnet-eastnet-x509-cr
ipsec auto --status | grep westnet-eastnet-x509-cr
echo "initdone"

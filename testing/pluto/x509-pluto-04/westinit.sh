/testing/guestbin/swan-prep --x509
certutil -D -n east -d /etc/ipsec.d
certutil -D -n east-ec -d /etc/ipsec.d
ipsec import /testing/x509/pkcs12/otherca/signedbyotherca.p12 
ipsec setup start
/testing/pluto/bin/wait-until-pluto-started
ipsec whack --debug-all --impair-retransmits
ipsec auto --add westnet-eastnet-x509-cr
ipsec auto --status | grep westnet-eastnet-x509-cr
echo "initdone"

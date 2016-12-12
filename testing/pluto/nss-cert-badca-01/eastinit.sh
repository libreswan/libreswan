/testing/guestbin/swan-prep --x509
certutil -d sql:/etc/ipsec.d -D -n west
certutil -d sql:/etc/ipsec.d -D -n east
certutil -A -i /testing/x509/cacerts/badca.crt -n "badca" -d sql:/etc/ipsec.d -t "CT,,"
pk12util -W foobar -K '' -d sql:/etc/ipsec.d -i /testing/x509/pkcs12/badca/badeast.p12
ipsec start
/testing/pluto/bin/wait-until-pluto-started
ipsec auto --add nss-cert
ipsec auto --status |grep nss-cert
echo "initdone"

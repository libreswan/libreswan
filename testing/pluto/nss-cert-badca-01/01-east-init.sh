/testing/guestbin/swan-prep --x509
ipsec certutil -D -n west
ipsec certutil -D -n east
ipsec certutil -A -i /testing/x509/cacerts/badca.crt -n "badca" -t "CT,,"
ipsec pk12util -W foobar -K '' -i /testing/x509/pkcs12/badca/badeast.p12
# check
ipsec certutil -L

ipsec start
../../guestbin/wait-until-pluto-started
ipsec auto --add nss-cert
ipsec auto --status |grep nss-cert
echo "initdone"

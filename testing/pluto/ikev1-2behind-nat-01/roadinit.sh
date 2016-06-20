/testing/guestbin/swan-prep --x509
echo -n "foobar" > /tm/pw
pk12util -W foobar -K '' -d sql:/etc/ipsec.d -i /testing/x509/pkcs12/mainca/north.p12
ipsec start
/testing/pluto/bin/wait-until-pluto-started
ipsec auto --add road
echo "initdone"

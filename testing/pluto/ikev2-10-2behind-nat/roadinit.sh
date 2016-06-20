/testing/guestbin/swan-prep --x509
pk12util -W foobar -K '' -d sql:/etc/ipsec.d -i /testing/x509/pkcs12/mainca/north.p12
ip addr add 192.1.3.210/24 dev eth0
ipsec start
/testing/pluto/bin/wait-until-pluto-started
ipsec auto --add road
echo "initdone"

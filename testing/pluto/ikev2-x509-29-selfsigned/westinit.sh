/testing/guestbin/swan-prep
pk12util -W foobar -K '' -d sql:/etc/ipsec.d -i /testing/x509/selfsigned/west-selfsigned.p12
pk12util -W foobar -K '' -d sql:/etc/ipsec.d -i /testing/x509/selfsigned/east-selfsigned.p12
pk12util -W foobar -K '' -d sql:/etc/ipsec.d -i /testing/x509/selfsigned/road-selfsigned.p12
ipsec start
/testing/pluto/bin/wait-until-pluto-started
ipsec auto --add west-x509
ipsec auto --add road-x509
echo "initdone"

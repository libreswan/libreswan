/testing/guestbin/swan-prep --nokeys
ipsec pk12util -W foobar -K '' -i /testing/x509/selfsigned/west-selfsigned.p12
ipsec pk12util -W foobar -K '' -i /testing/x509/selfsigned/east-selfsigned.p12
ipsec start
../../guestbin/wait-until-pluto-started
ipsec auto --add ikev2-x509
echo "initdone"

/testing/guestbin/swan-prep --x509
ipsec certutil -D -n west
# add second identity/cert
pk12util -W foobar -K '' -d sql:/etc/ipsec.d -i /testing/x509/pkcs12/otherca/othereast.p12
ipsec checknss --settrusts
ipsec start
../../guestbin/wait-until-pluto-started
# other is loaded in another test case, ikev2-x509-17-multicert-03
ipsec auto --add main
echo "initdone"

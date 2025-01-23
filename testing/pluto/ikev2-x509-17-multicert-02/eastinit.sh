/testing/guestbin/swan-prep --x509
ipsec certutil -D -n west
# add second identity/cert
ipsec pk12util -W foobar -K '' -i /testing/x509/pkcs12/otherca/othereast.p12
ipsec checknss --settrusts
# check
ipsec certutil -L

ipsec start
../../guestbin/wait-until-pluto-started
# other is loaded in another test case, ikev2-x509-17-multicert-03
ipsec auto --add main
echo "initdone"

/testing/guestbin/swan-prep --x509
certutil -D -n west -d sql:/etc/ipsec.d
# add second identity/cert
pk12util -W foobar -K '' -d sql:/etc/ipsec.d -i /testing/x509/pkcs12/otherca/othereast.p12
ipsec checknss --settrusts
ipsec start
/testing/pluto/bin/wait-until-pluto-started
# swapped order compared to ikev2-x509-17-multicert-03
ipsec auto --add main
ipsec auto --add other
echo "initdone"

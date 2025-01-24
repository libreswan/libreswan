/testing/guestbin/swan-prep --nokeys

ipsec pk12util -W foobar -K '' -i /testing/x509/real/mainca/east.all.p12
ipsec pk12util -W foobar -K '' -i /testing/x509/real/otherca/othereast.all.p12
ipsec checknss --settrusts
# check
ipsec certutil -L

ipsec start
../../guestbin/wait-until-pluto-started
# other is loaded in another test case, ikev2-x509-17-multicert-03
ipsec auto --add main
echo "initdone"

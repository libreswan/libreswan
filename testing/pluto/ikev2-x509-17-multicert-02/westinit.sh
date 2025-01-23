/testing/guestbin/swan-prep --x509
ipsec certutil -D -n east
ipsec pk12util -W foobar -K '' -i /testing/x509/pkcs12/otherca/otherwest.p12
ipsec checknss --settrusts
# check
ipsec certutil -L

ipsec start
../../guestbin/wait-until-pluto-started
ipsec whack --impair suppress_retransmits
ipsec auto --add main
#ipsec auto --add other
echo "initdone"

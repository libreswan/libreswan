/testing/guestbin/swan-prep --x509
certutil -D -n east -d sql:/etc/ipsec.d
pk12util -W foobar -K '' -d sql:/etc/ipsec.d -i /testing/x509/pkcs12/otherca/otherwest.p12
ipsec checknss --settrusts
ipsec start
/testing/pluto/bin/wait-until-pluto-started
ipsec whack --impair suppress-retransmits
ipsec auto --add main
#ipsec auto --add other
echo "initdone"

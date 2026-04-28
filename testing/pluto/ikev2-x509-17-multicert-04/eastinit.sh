/testing/guestbin/swan-prep --nokeys
/testing/x509/import.sh real/mainca/east.p12
# add second identity/cert
/testing/x509/import.sh otherca/othereast.p12
ipsec checknss --settrusts
ipsec start
../../guestbin/wait-until-pluto-started
# swapped order compared to ikev2-x509-17-multicert-03
ipsec auto --add main
ipsec auto --add other
echo "initdone"

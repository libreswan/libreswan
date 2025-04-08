/testing/guestbin/swan-prep --nokeys

/testing/x509/import.sh real/mainca/east.p12
/testing/x509/import.sh otherca/othereast.p12
ipsec checknss --settrusts
# check
ipsec certutil -L

ipsec start
../../guestbin/wait-until-pluto-started
# other is loaded in another test case, ikev2-x509-17-multicert-03
ipsec auto --add main
echo "initdone"

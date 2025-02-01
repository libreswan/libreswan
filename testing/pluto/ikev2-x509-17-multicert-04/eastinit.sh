/testing/guestbin/swan-prep --x509
ipsec certutil -D -n west
# add second identity/cert
/testing/x509/import.sh real/otherca/othereast.all.p12
ipsec checknss --settrusts
ipsec start
../../guestbin/wait-until-pluto-started
# swapped order compared to ikev2-x509-17-multicert-03
ipsec auto --add main
ipsec auto --add other
echo "initdone"

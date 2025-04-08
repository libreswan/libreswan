/testing/guestbin/swan-prep --x509
ipsec certutil -D -n west
# add second identity/cert
/testing/x509/import.sh otherca/othereast.p12
ipsec checknss --settrusts
ipsec start
../../guestbin/wait-until-pluto-started
# this causes main to match first, it should not switch since west uses main
ipsec auto --add other
ipsec auto --add main
echo "initdone"

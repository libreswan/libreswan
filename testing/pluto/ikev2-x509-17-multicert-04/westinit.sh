/testing/guestbin/swan-prep --x509
ipsec certutil -D -n east
/testing/x509/import.sh real/otherca/otherwest.all.p12
ipsec checknss --settrusts
ipsec start
../../guestbin/wait-until-pluto-started
ipsec whack --impair suppress_retransmits
ipsec auto --add main
#ipsec auto --add other
echo "initdone"

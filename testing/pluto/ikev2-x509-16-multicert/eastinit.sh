/testing/guestbin/swan-prep --nokeys

# add first identity/cert
/testing/x509/import.sh real/mainca/east.p12
# add second identity/cert
/testing/x509/import.sh otherca/othereast.p12
# check
ipsec certutil -L

ipsec start
../../guestbin/wait-until-pluto-started
ipsec add main
ipsec add other
echo "initdone"

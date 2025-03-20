/testing/guestbin/swan-prep --nokeys

# add first identity/cert
/testing/x509/import.sh real/mainca/east.all.p12
# add second identity/cert
/testing/x509/import.sh otherca/othereast.p12
# check
ipsec certutil -L

ipsec start
../../guestbin/wait-until-pluto-started
../../guestbin/ipsec-add.sh main other
echo "initdone"

/testing/guestbin/swan-prep --x509
ipsec certutil -D -n west
# add second identity/cert
#/testing/x509/import.sh real/otherca/othereast.all.p12
/testing/x509/import.sh real/mainca/north.all.p12
ipsec start
../../guestbin/wait-until-pluto-started
../../guestbin/ipsec-add.sh main-north main-east
echo "initdone"

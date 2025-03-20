/testing/guestbin/swan-prep --x509
ipsec certutil -D -n west
# add second identity/cert
#/testing/x509/import.sh otherca/othereast.p12
/testing/x509/import.sh real/mainca/north.all.p12
ipsec start
../../guestbin/wait-until-pluto-started
ipsec auto --add main-east
ipsec auto --add main-north
echo "initdone"

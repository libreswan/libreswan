/testing/guestbin/swan-prep --x509
ipsec certutil -D -n west
# add second identity/cert
#/testing/x509/import.sh real/otherca/othereast.all.p12
ipsec pk12util -W foobar -K '' -i /testing/x509/real/mainca/north.all.p12
ipsec start
../../guestbin/wait-until-pluto-started
ipsec auto --add main-east
ipsec auto --add main-north
echo "initdone"

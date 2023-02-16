/testing/guestbin/swan-prep --x509
ipsec certutil -D -n west
# add second identity/cert
#pk12util -W foobar -K '' -d sql:/etc/ipsec.d -i /testing/x509/pkcs12/otherca/othereast.p12
pk12util -W foobar -K '' -d sql:/etc/ipsec.d -i /testing/x509/pkcs12/mainca/north.p12
ipsec start
../../guestbin/wait-until-pluto-started
ipsec auto --add main-east
ipsec auto --add main-north
echo "initdone"

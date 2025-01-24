/testing/guestbin/swan-prep --nokeys

# add first identity/cert
ipsec pk12util -W foobar -K '' -i /testing/x509/real/mainca/east.all.p12
# add second identity/cert
ipsec pk12util -W foobar -K '' -i /testing/x509/real/otherca/othereast.all.p12
# check
ipsec certutil -L

ipsec start
../../guestbin/wait-until-pluto-started
../../guestbin/ipsec-add.sh main other
echo "initdone"

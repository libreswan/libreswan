/testing/guestbin/swan-prep --nokeys

# import west's cert (no CA)
ipsec certutil -A -t P,, -n west -i /testing/x509/real/mainca/west.end.cert
# import fake east cert+key (again no CA)
ipsec pk12util -W foobar -K '' -i /testing/x509/fake/mainca/east.end.p12
# confirm
ipsec certutil -L

ipsec start
../../guestbin/wait-until-pluto-started
ipsec auto --add ikev2-westnet-eastnet-x509-cr
echo "initdone"

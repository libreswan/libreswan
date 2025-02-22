/testing/guestbin/swan-prep --nokeys

# import real west end cert
/testing/x509/import.sh real/mainca/west.end.cert
# import fake east end cert
ipsec pk12util -W foobar -K '' -i /testing/x509/fake/mainca/east.end.p12
# confirm
ipsec certutil -L

ipsec start
../../guestbin/wait-until-pluto-started
ipsec auto --add ikev2-westnet-eastnet-x509-cr
echo "initdone"

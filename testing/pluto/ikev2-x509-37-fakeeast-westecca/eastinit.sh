/testing/guestbin/swan-prep --nokeys

# import real west+mainca
ipsec pk12util -W foobar -K '' -i /testing/x509/pkcs12/mainca/west.p12
# delete real main CA
ipsec certutil -D -n "Libreswan test CA for mainca - Libreswan"
# import fake east cert and fake main CA
ipsec pk12util -W foobar -K '' -i /testing/x509/fake/pkcs12/mainca/east.p12
# remove main CA - so real-west cannot be verified - rely on cert=west
ipsec certutil -D -n "Libreswan test CA for mainca - Libreswan"

ipsec start
../../guestbin/wait-until-pluto-started
ipsec auto --add ikev2-westnet-eastnet-x509-cr
echo "initdone"

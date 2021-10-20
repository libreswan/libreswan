/testing/guestbin/swan-prep

# import real west+mainca
pk12util -W foobar -K '' -d sql:/etc/ipsec.d -i /testing/x509/pkcs12/mainca/west.p12
# delete real main CA
certutil -D -d sql:/etc/ipsec.d -n "Libreswan test CA for mainca - Libreswan"
# import fake east cert and fake main CA
pk12util -W foobar -K '' -d sql:/etc/ipsec.d -i /testing/x509/fake/pkcs12/mainca/east.p12
# remove main CA - so real-west cannot be verified - rely on cert=west
certutil -D -d sql:/etc/ipsec.d -n "Libreswan test CA for mainca - Libreswan"

ipsec start
../../guestbin/wait-until-pluto-started
ipsec auto --add ikev2-westnet-eastnet-x509-cr
echo "initdone"

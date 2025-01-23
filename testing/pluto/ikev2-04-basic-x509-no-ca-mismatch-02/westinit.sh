/testing/guestbin/swan-prep --x509 --x509name north
# delete the CA, both ends hardcode both certificates
ipsec certutil -D -n "Libreswan test CA for mainca - Libreswan"
# add a random cert and CA, unrelated to the actual test
ipsec pk12util -W foobar -K '' -i /testing/x509/pkcs12/otherca/otherwest.p12
# check
ipsec certutil -L

ipsec start
../../guestbin/wait-until-pluto-started
ipsec auto --add westnet-eastnet-ikev2
ipsec auto --status | grep westnet-eastnet-ikev2
echo "initdone"

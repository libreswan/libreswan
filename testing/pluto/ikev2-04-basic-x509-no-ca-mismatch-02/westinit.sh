/testing/guestbin/swan-prep --x509 --x509name north
# delete the CA, both ends hardcode both certificates
certutil -D -n "Libreswan test CA for mainca - Libreswan" -d sql:/etc/ipsec.d
certutil -D -n "east-ec" -d sql:/etc/ipsec.d
# add a random cert and CA, unrelated to the actual test
pk12util -W foobar -K '' -d sql:/etc/ipsec.d -i /testing/x509/pkcs12/otherca/otherwest.p12
ipsec start
/testing/pluto/bin/wait-until-pluto-started
ipsec auto --add westnet-eastnet-ikev2
ipsec auto --status | grep westnet-eastnet-ikev2
echo "initdone"

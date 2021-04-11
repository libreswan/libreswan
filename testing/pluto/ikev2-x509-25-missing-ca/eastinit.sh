/testing/guestbin/swan-prep --x509
certutil -D -n west -d sql:/etc/ipsec.d
ipsec start
../../guestbin/wait-until-pluto-started
# remove CA cert
certutil -D -d sql:/etc/ipsec.d -n "Libreswan test CA for mainca - Libreswan"
# insert a different CAcert to avoid NSS aborting for having no CA at all
pk12util -W foobar -K '' -d sql:/etc/ipsec.d -i /testing//x509/pkcs12/badca/badeast.p12
ipsec auto --add ikev2-westnet-eastnet-x509-cr
echo "initdone"

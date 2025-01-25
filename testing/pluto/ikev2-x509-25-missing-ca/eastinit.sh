/testing/guestbin/swan-prep --x509
ipsec certutil -D -n west
ipsec start
../../guestbin/wait-until-pluto-started
# remove CA cert
ipsec certutil -D -n "Libreswan test CA for mainca - Libreswan"
# insert a different CAcert to avoid NSS aborting for having no CA at all
ipsec pk12util -W foobar -K '' -i /testing//x509/pkcs12/badca/badeast.p12
# check
ipsec certutil -L

ipsec auto --add ikev2-westnet-eastnet-x509-cr
echo "initdone"

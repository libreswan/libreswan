/testing/guestbin/swan-prep --x509
ipsec certutil -D -n west
# remove CA cert
ipsec certutil -D -n "Libreswan test CA for mainca - Libreswan"
ipsec start
../../guestbin/wait-until-pluto-started
ipsec auto --add ikev2-westnet-eastnet-x509-cr
echo "initdone"

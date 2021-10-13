/testing/guestbin/swan-prep --x509
certutil -D -n west -d sql:/etc/ipsec.d
# remove CA cert
certutil -D -d sql:/etc/ipsec.d -n "Libreswan test CA for mainca - Libreswan"
ipsec start
../../guestbin/wait-until-pluto-started
ipsec auto --add ikev2-westnet-eastnet-x509-cr
echo "initdone"

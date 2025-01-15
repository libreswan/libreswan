/testing/guestbin/swan-prep --x509
# delete the CA, both ends hardcode both certificates
ipsec certutil -D -n "Libreswan test CA for mainca - Libreswan"
ipsec start
../../guestbin/wait-until-pluto-started
ipsec auto --add westnet-eastnet-ikev2
ipsec auto --status | grep westnet-eastnet-ikev2
echo "initdone"

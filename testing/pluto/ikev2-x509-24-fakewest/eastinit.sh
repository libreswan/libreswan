/testing/guestbin/swan-prep --x509

# remove CA
ipsec certutil -D -n "Libreswan test CA for mainca - Libreswan"
# this leaves real east and real west certs. other end will use
# different fake west cert
ipsec certutil -L

ipsec start
../../guestbin/wait-until-pluto-started
ipsec auto --add westnet-eastnet-ikev2
ipsec auto --status | grep westnet-eastnet-ikev2
echo "initdone"

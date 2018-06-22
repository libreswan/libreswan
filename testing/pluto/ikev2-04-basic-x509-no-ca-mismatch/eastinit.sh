/testing/guestbin/swan-prep --x509
# delete the CA, both ends hardcode both certificates
certutil -D -n "Libreswan test CA for mainca - Libreswan" -d sql:/etc/ipsec.d
certutil -D -n "west-ec" -d sql:/etc/ipsec.d
ipsec start
/testing/pluto/bin/wait-until-pluto-started
ipsec auto --add westnet-eastnet-ikev2
ipsec auto --status | grep westnet-eastnet-ikev2
echo "initdone"

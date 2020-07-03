/testing/guestbin/swan-prep --x509
# delete real west cert and real main CA
certutil -D -n west -d sql:/etc/ipsec.d
certutil -D -d sql:/etc/ipsec.d -n "Libreswan test CA for mainca - Libreswan"
# import fake one
pk12util -W foobar -K '' -d sql:/etc/ipsec.d -i /testing/x509/fake/pkcs12/mainca/west.p12
# remove (fake) CA
certutil -D -d sql:/etc/ipsec.d -n "Libreswan test CA for mainca - Libreswan"
# confirm that the network is alive
../../pluto/bin/wait-until-alive -I 192.0.1.254 192.0.2.254
# ensure that clear text does not get through
iptables -A INPUT -i eth1 -s 192.0.2.0/24 -j DROP
iptables -I INPUT -m policy --dir in --pol ipsec -j ACCEPT
# confirm clear text does not get through
../../pluto/bin/ping-once.sh --down -I 192.0.1.254 192.0.2.254
ipsec start
/testing/pluto/bin/wait-until-pluto-started
ipsec auto --add westnet-eastnet-ikev2
ipsec auto --status | grep westnet-eastnet-ikev2
echo "initdone"

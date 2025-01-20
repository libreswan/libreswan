/testing/guestbin/swan-prep --x509

# delete real west cert and real main CA
ipsec certutil -D -n west
ipsec certutil -D -n "Libreswan test CA for mainca - Libreswan"
# import fake one
ipsec pk12util -W foobar -K '' -i /testing/x509/fake/pkcs12/mainca/west.p12
# remove (fake) CA
ipsec certutil -D -n "Libreswan test CA for mainca - Libreswan"
# confirm
ipsec certutil -L

# confirm that the network is alive
../../guestbin/wait-until-alive -I 192.0.1.254 192.0.2.254
# ensure that clear text does not get through
iptables -A INPUT -i eth1 -s 192.0.2.0/24 -j DROP
iptables -I INPUT -m policy --dir in --pol ipsec -j ACCEPT
# confirm clear text does not get through
../../guestbin/ping-once.sh --down -I 192.0.1.254 192.0.2.254
ipsec start
../../guestbin/wait-until-pluto-started
ipsec auto --add westnet-eastnet-ikev2
ipsec auto --status | grep westnet-eastnet-ikev2
echo "initdone"

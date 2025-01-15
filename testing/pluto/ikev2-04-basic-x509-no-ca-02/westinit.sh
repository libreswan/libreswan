/testing/guestbin/swan-prep --x509
# delete the CA, both ends hardcode both certificates
ipsec certutil -D -n "Libreswan test CA for mainca - Libreswan"
# load a distraction CA
ipsec pk12util -W foobar -K '' -i /testing/x509/pkcs12/otherca/otherwest.p12
ipsec certutil -M -n 'Libreswan test CA for otherca - Libreswan' -t 'CT,,'
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

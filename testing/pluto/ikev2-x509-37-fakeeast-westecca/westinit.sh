/testing/guestbin/swan-prep --eccert

# import real west+mainca
pk12util -W foobar -K '' -d sql:/etc/ipsec.d -i /testing/x509/pkcs12/mainca/west.p12
# delete real main CA
certutil -D -d sql:/etc/ipsec.d -n "Libreswan test CA for mainca - Libreswan"
# so only CA is bogus
pk12util -W foobar -K '' -d sql:/etc/ipsec.d -i /testing/x509/fake/pkcs12/mainec/mainec.p12

# confirm that the network is alive
../../pluto/bin/wait-until-alive -I 192.0.1.254 192.0.2.254
# ensure that clear text does not get through
iptables -A INPUT -i eth1 -s 192.0.2.0/24 -j DROP
iptables -I INPUT -m policy --dir in --pol ipsec -j ACCEPT
# confirm clear text does not get through
../../pluto/bin/ping-once.sh --down -I 192.0.1.254 192.0.2.254
ipsec start
/testing/pluto/bin/wait-until-pluto-started
ipsec auto --add ikev2-westnet-eastnet-x509-cr
ipsec whack --impair suppress-retransmits
echo "initdone"

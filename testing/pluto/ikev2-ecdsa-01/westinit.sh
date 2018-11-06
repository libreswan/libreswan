/testing/guestbin/swan-prep
# confirm that the network is alive
../../pluto/bin/wait-until-alive -I 192.0.1.254 192.0.2.254
# ensure that clear text does not get through
iptables -A INPUT -i eth1 -s 192.0.2.0/24 -j LOGDROP
iptables -I INPUT -m policy --dir in --pol ipsec -j ACCEPT
# confirm clear text does not get through
../../pluto/bin/ping-once.sh --down -I 192.0.1.254 192.0.2.254
/usr/bin/pk12util -i /testing/x509/strongswan/strongWest.p12 -d sql:/etc/ipsec.d -w /testing/x509/nss-pw
# Tuomo: why doesn't ipsec checknss --settrust work here?
certutil -M -d sql:/etc/ipsec.d -n "strongSwan CA - strongSwan" -t CT,,
#ipsec start
ipsec _stackmanager start
ipsec pluto --config /etc/ipsec.conf --leak-detective
/testing/pluto/bin/wait-until-pluto-started
ipsec auto --add westnet-eastnet-ikev2
ipsec whack --impair suppress-retransmits
echo "initdone"

/testing/guestbin/swan-prep --x509
certutil -D -n east -d sql:/etc/ipsec.d
# confirm that the network is alive
../../pluto/bin/wait-until-alive -I 192.0.1.254 192.0.2.254
# ensure that clear text does not get through
iptables -A INPUT -i eth1 -s 192.0.2.0/24 -j LOGDROP
iptables -I INPUT -m policy --dir in --pol ipsec -j ACCEPT
# confirm with a ping
ping -n -c 4 -I 192.0.1.254 192.0.2.254
ipsec start
/testing/pluto/bin/wait-until-pluto-started
ipsec whack --impair suppress-retransmits
ipsec auto --add ikev2-westnet-eastnet-x509-cr
echo "initdone"

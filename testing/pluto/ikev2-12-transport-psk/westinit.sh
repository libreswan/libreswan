/testing/guestbin/swan-prep
# confirm that the network is alive
../../pluto/bin/wait-until-alive -I 192.1.2.45 192.1.2.23
# ensure that clear text does not get through
iptables -A INPUT -i eth1 -s 192.1.2.23/32 -p icmp -j DROP
iptables -I INPUT -m policy --dir in --pol ipsec -j ACCEPT
# confirm clear text does not get through
../../pluto/bin/ping-once.sh --down -I 192.1.2.45 192.1.2.23
ipsec start
/testing/pluto/bin/wait-until-pluto-started
ipsec auto --add ipv4-psk-ikev2-transport
ipsec auto --status | grep ipv4-psk-ikev2-transport
ipsec whack --impair suppress-retransmits
echo "initdone"

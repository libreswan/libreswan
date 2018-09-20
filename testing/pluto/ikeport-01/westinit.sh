/testing/guestbin/swan-prep
# confirm that the network is alive
../../pluto/bin/wait-until-alive -I 192.0.1.254 192.0.2.254
# ensure that clear text does not get through
iptables -A INPUT -i eth1 -s 192.0.2.0/24 -j LOGDROP
# confirm with a ping
ping -n -c 4 -I 192.0.1.254 192.0.2.254
ipsec _stackmanager start
ipsec pluto --config /etc/ipsec.conf --natikeport 1000 --ikeport 999
/testing/pluto/bin/wait-until-pluto-started
ipsec auto --add porttest
ipsec whack --impair suppress-retransmits
ipsec auto --status
echo "initdone"

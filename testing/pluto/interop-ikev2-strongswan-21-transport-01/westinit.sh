/testing/guestbin/swan-prep
# confirm that the network is alive
../../pluto/bin/wait-until-alive -I 192.1.2.45 192.1.2.23
# ensure that clear text does not get through
iptables -A INPUT -i eth1 -s 192.1.2.23/32 -p icmp -j LOGDROP
iptables -I INPUT -m policy --dir in --pol ipsec -j ACCEPT
# confirm clear text does not get through
ping -n -c 4 -I 192.1.2.45 192.1.2.23
ipsec start
/testing/pluto/bin/wait-until-pluto-started
ipsec auto --add westnet-eastnet-ikev2
echo "initdone"

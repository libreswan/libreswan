/testing/guestbin/swan-prep
# confirm that the network is alive
../../pluto/bin/wait-until-alive -I 192.0.1.254 192.0.2.254
# confirm that clear text is dead
! ../../pluto/bin/wait-until-alive -I 192.1.2.45 192.1.2.23
# make sure that clear text does not get through
iptables -A INPUT -i eth1 -s 192.1.2.23/32 -p icmp -j LOGDROP
iptables -I INPUT -m policy --dir in --pol ipsec -j ACCEPT
# confirm with a ping
ping -n -c 4 -I 192.1.2.45 192.1.2.23
ipsec start
/testing/pluto/bin/wait-until-pluto-started
ipsec auto --add west-east
ipsec auto --add west-east-passthrough
ipsec auto --route west-east-passthrough
echo "initdone"

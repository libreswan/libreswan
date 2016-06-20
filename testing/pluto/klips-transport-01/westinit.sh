/testing/guestbin/swan-prep
# confirm that the network is alive
../../pluto/bin/wait-until-alive -I 192.0.1.254 192.0.2.254
echo "transmit text" | nc 192.1.2.23 3
# make sure that clear text does not get through
iptables -A INPUT -i eth1 -s 192.1.2.23 -p tcp --sport 3 -j REJECT
iptables -I INPUT -m policy --dir in --pol ipsec -j ACCEPT
ping -n -c 4 192.0.2.254
echo "transmitted test" | nc 192.1.2.23 3
ipsec start
/testing/pluto/bin/wait-until-pluto-started
ipsec auto --add west-east-port3
ipsec auto --add west-east-pass
ipsec auto --route west-east-pass
ipsec whack --trafficstatus
echo "initdone"

/testing/guestbin/swan-prep
../../pluto/bin/wait-until-alive -I 192.0.1.254 192.0.2.254
# ensure that clear text does not get through
iptables -A INPUT -i eth1 -s 192.0.2.254/32 -j LOGDROP
iptables -I INPUT -m policy --dir in --pol ipsec -j ACCEPT
# confirm clear text does not get through
ping -c 4 -n -I 192.0.3.254 192.0.2.254
ipsec start
/testing/pluto/bin/wait-until-pluto-started
ipsec auto --add northnet-eastnet-nonat
echo "initdone"

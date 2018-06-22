/testing/guestbin/swan-prep
ip addr add 192.0.1.111/24 dev eth0
# confirm that the network is alive
../../pluto/bin/wait-until-alive -I 192.0.1.254 192.0.2.254
../../pluto/bin/wait-until-alive -I 192.0.1.111 192.0.2.111
# ensure that clear text does not get through
iptables -A INPUT -i eth1 -s 192.0.2.0/24 -j LOGDROP
iptables -I INPUT -m policy --dir in --pol ipsec -j ACCEPT
# confirm with a ping
ping -n -c 4 -I 192.0.1.254 192.0.2.254
ipsec start
/testing/pluto/bin/wait-until-pluto-started
ipsec auto --add westnet-eastnet-ah-md5
ipsec auto --add westnet-eastnet-ah-sha1
echo "initdone"

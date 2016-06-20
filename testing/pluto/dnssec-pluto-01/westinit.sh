/testing/guestbin/swan-prep
# confirm that the network is alive
../../pluto/bin/wait-until-alive -I 192.0.1.254 192.0.2.254
# make sure that clear text does not get through
iptables -A INPUT -i eth1 -s 192.0.2.0/24 -j LOGDROP
iptables -I INPUT -m policy --dir in --pol ipsec -j ACCEPT
# confirm with a ping
ping -n -c 4 -I 192.0.1.254 192.0.2.254
# ensure this test cases has USE_DNSSEC compiled pluto
ipsec pluto --version |sed "s/^.*DNSSEC.*//"
echo 192.1.2.23 east-from-hosts-file.example.com east-from-hosts-file >> /etc/hosts
ipsec start
/testing/pluto/bin/wait-until-pluto-started
ipsec auto --add westnet-eastnet-etc-hosts
ipsec auto --status | egrep "oriented|east-from-hosts"
echo "initdone"

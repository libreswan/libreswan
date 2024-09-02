/testing/guestbin/swan-prep --hostkeys
# confirm that the network is alive
../../guestbin/wait-until-alive -I 192.0.1.254 192.0.2.254
# ensure that clear text does not get through
iptables -A INPUT -i eth1 -s 192.0.2.0/24 -j DROP
iptables -I INPUT -m policy --dir in --pol ipsec -j ACCEPT
# confirm clear text does not get through
../../guestbin/ping-once.sh --down -I 192.0.1.254 192.0.2.254
# ensure this test cases has USE_DNSSEC compiled pluto
ipsec pluto --version |sed "s/^.*DNSSEC.*//"
echo 192.1.2.23 east-from-hosts-file.example.com east-from-hosts-file >> /etc/hosts
ipsec start
../../guestbin/wait-until-pluto-started
ipsec auto --add westnet-eastnet-etc-hosts
ipsec auto --status | grep -E "oriented|east-from-hosts"
echo "initdone"

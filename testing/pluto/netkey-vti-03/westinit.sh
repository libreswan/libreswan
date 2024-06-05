/testing/guestbin/swan-prep
# confirm that the network is alive
../../guestbin/wait-until-alive -I 192.0.1.254 192.0.2.254
# ensure that clear text does not get through
iptables -A INPUT -i eth1 -s 192.0.2.0/24 -j DROP
iptables -A INPUT -i eth1 -s 10.0.2.0/24 -j DROP
iptables -I INPUT -m policy --dir in --pol ipsec -j ACCEPT
# confirm clear text does not get through
../../guestbin/ping-once.sh --down -I 192.0.1.254 192.0.2.254
../../guestbin/ip.sh address add 10.0.1.254 dev eth0
ipsec start
../../guestbin/wait-until-pluto-started
ipsec auto --add westnet-eastnet-vti-01
ipsec auto --add westnet-eastnet-vti-02
# remove the regular route for 192.0.2.0/24
../../guestbin/ip.sh route del 192.0.2.0/24
echo "initdone"

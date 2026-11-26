/testing/guestbin/swan-prep --nokeys
../../guestbin/wait-until-alive -I 192.0.1.254 192.0.2.254
iptables -A INPUT -i eth1 -s 192.0.2.0/24 -j DROP
iptables -I INPUT -m policy --dir in --pol ipsec -j ACCEPT
../../guestbin/ping-once.sh --down -I 192.0.1.254 192.0.2.254
ipsec start
../../guestbin/wait-until-pluto-started
ipsec add west
echo "initdone"

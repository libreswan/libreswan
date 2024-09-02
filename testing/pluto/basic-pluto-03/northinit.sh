/testing/guestbin/swan-prep --hostkeys
../../guestbin/wait-until-alive -I 192.0.3.254 192.0.2.254

# ensure that clear text does not get through
iptables -A INPUT -i eth1 -s 192.0.2.254/32 -j DROP
iptables -I INPUT -m policy --dir in --pol ipsec -j ACCEPT

ipsec start
../../guestbin/wait-until-pluto-started
ipsec whack --impair suppress_retransmits
ipsec auto --add northnet-eastnet-nonat
ipsec auto --status

echo "initdone"

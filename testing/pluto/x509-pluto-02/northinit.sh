/testing/guestbin/swan-prep --x509
../../guestbin/wait-until-alive -I 192.0.3.254 192.0.2.254

# ensure that clear text does not get through
iptables -I INPUT -i eth1 -s 192.0.2.0/24 -j DROP
iptables -I INPUT -m policy --dir in --pol ipsec -j ACCEPT

ipsec start
../../guestbin/wait-until-pluto-started
ipsec whack --impair suppress-retransmits
ipsec auto --add north-east-x509-pluto-02
ipsec auto --status | grep north-east-x509-pluto-02

echo "initdone"

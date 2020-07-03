/testing/guestbin/swan-prep --x509
# ensure that clear text does not get through
iptables -A INPUT -i eth1 -s 192.0.2.254/32 -j DROP
iptables -I INPUT -m policy --dir in --pol ipsec -j ACCEPT
ipsec start
/testing/pluto/bin/wait-until-pluto-started
ipsec auto --add northnet-eastnet-nat
ipsec whack --impair suppress-retransmits
echo "initdone"

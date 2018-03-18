/testing/guestbin/swan-prep --x509
iptables -A INPUT -i eth1 -s 192.0.1.0/24 -j DROP
iptables -A INPUT -i eth1 -s 192.0.2.0/24 -j DROP
iptables -I INPUT -m policy --dir in --pol ipsec -j ACCEPT
ipsec start
/testing/pluto/bin/wait-until-pluto-started
ipsec whack --impair suppress-retransmits
ipsec auto --add road-east-x509-ipv4
echo "initdone"

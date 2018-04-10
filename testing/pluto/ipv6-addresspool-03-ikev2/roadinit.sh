/testing/guestbin/swan-prep
../../pluto/bin/wait-until-alive 192.0.2.254
iptables -A INPUT -i eth1 -s 192.0.2.254 -p icmp -j DROP
iptables -I INPUT -m policy --dir in --pol ipsec -j ACCEPT
../../pluto/bin/ping-once.sh --down 192.0.2.254
ipsec start
/testing/pluto/bin/wait-until-pluto-started
ipsec whack --impair suppress-retransmits
ipsec auto --add road
echo "initdone"

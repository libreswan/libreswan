/testing/guestbin/swan-prep --46
../../pluto/bin/wait-until-alive 2001:db8:0:2::254
ip6tables -A INPUT -i eth0 -s 2001:db8:0:2::254 -p ipv6-icmp -j DROP
ip6tables -I INPUT -m policy --dir in --pol ipsec -j ACCEPT
../../pluto/bin/ping-once.sh --down 2001:db8:0:2::254
ipsec start
/testing/pluto/bin/wait-until-pluto-started
ipsec whack --impair suppress-retransmits
ipsec auto --add road
echo "initdone"

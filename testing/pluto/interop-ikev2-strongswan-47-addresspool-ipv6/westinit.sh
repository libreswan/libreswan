/testing/guestbin/swan-prep --userland strongswan --46
../../pluto/bin/wait-until-alive 2001:db8:0:2::254
ip6tables -A INPUT -i eth1 -s 2001:db8:0:2::254 -p ipv6-icmp -j DROP
ip6tables -I INPUT -m policy --dir in --pol ipsec -j ACCEPT
../../pluto/bin/ping-once.sh --down 2001:db8:0:2::254
../../pluto/bin/strongswan-start.sh
echo "initdone"

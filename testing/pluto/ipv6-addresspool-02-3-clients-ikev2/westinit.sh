/testing/guestbin/swan-prep --46
../../guestbin/wait-until-alive 2001:db8:0:2::254
# add two extra IPv6 addresses
ip addr show dev eth1 | grep 2001:db8:1:2::46  || ip addr add 2001:db8:1:2::46/64 dev eth1
ip addr show dev eth1 | grep 2001:db8:1:2::47  || ip addr add 2001:db8:1:2::47/64 dev eth1
ip6tables -A INPUT -i eth1 -s 2001:db8:0:2::254 -p ipv6-icmp -j DROP
ip6tables -I INPUT -m policy --dir in --pol ipsec -j ACCEPT
../../guestbin/ping-once.sh --down 2001:db8:0:2::254
ipsec start
../../guestbin/wait-until-pluto-started
echo "initdone"

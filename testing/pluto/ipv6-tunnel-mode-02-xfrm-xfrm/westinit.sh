/testing/guestbin/swan-prep --46 --hostkeys
# confirm that the network is alive
../../guestbin/ping-once.sh --up -I 2001:db8:1:2::45 2001:db8:1:2::23
# ensure that clear text does not get through
ip6tables -A INPUT -i eth1 -s 2001:db8:1:2::23 -p ipv6-icmp --icmpv6-type echo-reply -j DROP
ip6tables -I INPUT -m policy --dir in --pol ipsec -j ACCEPT
# confirm clear text does not get through
../../guestbin/ping-once.sh --down -I 2001:db8:1:2::45 2001:db8:1:2::23
ipsec start
../../guestbin/wait-until-pluto-started
ipsec auto --add v6-tunnel
ipsec auto --status
echo "initdone"

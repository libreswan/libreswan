/testing/guestbin/swan-prep --46
# confirm that the network is alive
ping6 -n -c 4 2001:db8:1:2::23
# make sure that clear text does not get through
ip6tables -A INPUT -i eth0 -s 2001:db8:1:2::23 -p ipv6-icmp --icmpv6-type echo-request  -j DROP
ip6tables -A INPUT -i eth0 -s 2001:db8:1:2::23 -p ipv6-icmp --icmpv6-type echo-reply  -j DROP
# confirm with a ping to east-in
ping6 -n -c 4 2001:db8:1:2::23
ipsec _stackmanager start
/usr/local/libexec/ipsec/pluto --config /etc/ipsec.conf
/testing/pluto/bin/wait-until-pluto-started
ipsec auto --add v6-tunnel-east-road
ipsec auto --status
echo "initdone"

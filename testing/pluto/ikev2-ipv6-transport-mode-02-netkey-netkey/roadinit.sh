/testing/guestbin/swan-prep --46
# confirm that the network is alive
ping6 -n -c 4 -I 2001:db8:1:3::209 2001:db8:1:2::23
ip6tables -A INPUT -i eth0 -s 2001:db8:1:2::23 -p ipv6-icmp --icmpv6-type echo-reply -j LOGDROP
ip6tables -I INPUT -m policy --dir in --pol ipsec -j ACCEPT
# confirm with a ping
ping6 -n -c 4 -I 2001:db8:1:3::209 2001:db8:1:2::23
ipsec start
/testing/pluto/bin/wait-until-pluto-started
ipsec auto --add v6-transport
ipsec auto --status |grep v6-transport
echo "initdone"

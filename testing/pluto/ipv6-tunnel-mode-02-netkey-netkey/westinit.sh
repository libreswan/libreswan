/testing/guestbin/swan-prep
# confirm that the network is alive
ping6 -n -c 4 -I 2001:db8:1:2::45 2001:db8:1:2::23
# make sure that clear text does not get through
ip6tables -A INPUT -i eth1 -s 2001:db8:1:2::45 -p icmp -j DROP
# confirm with a ping to east-in
ping6 -n -c 4 -I 2001:db8:1:2::45 2001:db8:1:2::23
ipsec _stackmanager start
/usr/local/libexec/ipsec/pluto --config /etc/ipsec.conf
/testing/pluto/bin/wait-until-pluto-started
ipsec auto --add v6-tunnel
ipsec auto --status
echo "initdone"

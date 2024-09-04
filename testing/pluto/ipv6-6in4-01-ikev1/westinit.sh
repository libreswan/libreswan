/testing/guestbin/swan-prep --46 --hostkeys
# confirm that the network is alive
ping6 -n -q -c 4 -I 2001:db8:0:1::254 2001:db8:0:2::254
# ensure that clear text does not get through
ip6tables -A INPUT -i eth1 -s 2001:db8:0:2::254 -j DROP
ip6tables -I INPUT -m policy --dir in --pol ipsec -j ACCEPT
# confirm clear text does not get through
ping6 -n -q -c 4 -I 2001:db8:0:1::254 2001:db8:0:2::254
ipsec start
../../guestbin/wait-until-pluto-started
ipsec auto --add westnet-eastnet-6in4
ipsec status | grep westnet-eastnet-6in4
ipsec whack --impair suppress_retransmits
echo "initdone"

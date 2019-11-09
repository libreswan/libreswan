/testing/guestbin/swan-prep
# confirm that the network is alive
../../pluto/bin/wait-until-alive -I 192.1.2.45 192.1.2.23
# ensure that clear text does not get through
iptables -A INPUT -i eth0 -s 192.1.2.23/32 -p icmp -j LOGDROP
iptables -I INPUT -m policy --dir in --pol ipsec -j ACCEPT
# confirm clear text does not get through
ping -n -c 4 -I 192.1.2.45 192.1.2.23
ipsec start
/testing/pluto/bin/wait-until-pluto-started
ipsec auto --add west-east
ip xfrm policy add src 192.1.2.23/32 dst 192.1.2.45/32 proto tcp sport 222 dport 222 ptype main priority 1440 dir in
ip xfrm policy add src 192.1.2.45/32 dst 192.1.2.23/32 proto tcp sport 222 dport 222 ptype main priority 1440 dir out
ip xfrm policy add src 192.1.2.23/32 dst 192.1.2.45/32 proto tcp sport 222 dport 222 ptype main priority 1440 dir fwd
echo "initdone"

/testing/guestbin/swan-prep --hostkeys
# confirm that the network is alive
../../guestbin/wait-until-alive -I 192.1.2.45 192.1.2.23
# ensure that clear text does not get through
iptables -A INPUT -i eth0 -s 192.1.2.23/32 -p icmp -j DROP
iptables -I INPUT -m policy --dir in --pol ipsec -j ACCEPT
# confirm clear text does not get through
../../guestbin/ping-once.sh --up -I 192.1.2.45 192.1.2.23
ipsec start
../../guestbin/wait-until-pluto-started
ipsec auto --add west-east
ip xfrm policy add src 192.1.2.23/32 dst 192.1.2.45/32 proto tcp sport 7 dport 7 ptype main priority 1440 dir in
ip xfrm policy add src 192.1.2.45/32 dst 192.1.2.23/32 proto tcp sport 7 dport 7 ptype main priority 1440 dir out
ip xfrm policy add src 192.1.2.23/32 dst 192.1.2.45/32 proto tcp sport 7 dport 7 ptype main priority 1440 dir fwd
echo "initdone"

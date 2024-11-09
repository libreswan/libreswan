/testing/guestbin/swan-prep --hostkeys
ipsec start
../../guestbin/wait-until-pluto-started
ip xfrm policy add src 192.1.2.45/32 dst 192.1.2.23/32 proto tcp sport 7 dport 7 ptype main priority 1440 dir in
ip xfrm policy add src 192.1.2.23/32 dst 192.1.2.45/32 proto tcp sport 7 dport 7 ptype main priority 1440 dir out
ip xfrm policy add src 192.1.2.23/32 dst 192.1.2.45/32 proto tcp sport 7 dport 7 ptype main priority 1440 dir fwd
ipsec auto --add west-east
../../guestbin/echo-server.sh -tcp -4 7 -daemon
echo "initdone"

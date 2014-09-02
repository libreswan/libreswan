/testing/guestbin/swan-prep
ipsec setup start
/testing/pluto/bin/wait-until-pluto-started
ip xfrm policy add src 192.1.2.45/32 dst 192.1.2.23/32 proto tcp sport 222 dport 222 ptype main priority 1440 dir in
ip xfrm policy add src 192.1.2.23/32 dst 192.1.2.45/32 proto tcp sport 222 dport 222 ptype main priority 1440 dir out
ip xfrm policy add src 192.1.2.23/32 dst 192.1.2.45/32 proto tcp sport 222 dport 222 ptype main priority 1440 dir fwd
ipsec auto --add west-east
nc -4 -l 192.1.2.23 222 &
echo "initdone"

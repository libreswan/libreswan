#sleep 30; # enable to get time to attach ip xfrm monitor
# We should already have a %trap policy because we have a 192.1.2.23/32 group-instance
ip -o xfrm pol | grep 192.1.2.23
# trigger a private-or-clear and check for shunt and shunt expiry
../../guestbin/ping-once.sh --down -I 192.1.3.209 192.1.2.23
# wait on OE retransmits and rekeying
sleep 3
# should show nothing in shuntstatus (shunt is not bare, but with conn), should show up in xfrm policy and show partial STATE
ipsec whack --shuntstatus
ip -o xfrm pol | grep 192.1.2.23
ipsec status | grep STATE_
sleep 10
# should show %pass in shuntstatus and xfrm policy and without partial STATE
ipsec whack --shuntstatus
ip -o xfrm pol | grep 192.1.2.23
ipsec status | grep STATE_
sleep 35
# should show no more shunts for 192.1.2.23, but SHOULD show our %trap xfrm policy and no STATE's
ipsec whack --shuntstatus
ip -o xfrm pol | grep 192.1.2.23
ipsec status | grep STATE_

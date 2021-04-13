#sleep 30; # enable to get time to attach ip xfrm monitor
# trigger a private-or-clear and check for shunt and shunt expiry
ping -n -q -c 1 -I 192.1.3.209 192.1.2.23
# wait on OE retransmits and rekeying
sleep 3
# should show nothing in shuntstatus (shunt is not bare, but with conn), should show up in xfrm policy and show partial STATE
ipsec whack --shuntstatus
ip -o xfrm pol | grep 192.1.2.23
ipsec status | grep STATE_
sleep 10
# should show pass in shuntstatus and xfrm policy and without partial STATE
ipsec whack --shuntstatus
ip -o xfrm pol | grep 192.1.2.23
ipsec status | grep STATE_
sleep 35
# should show no more shunts for 192.1.2.23, no xfrm policy and no STATE's
ipsec whack --shuntstatus
ip -o xfrm pol | grep 192.1.2.23
ipsec status | grep STATE_
# repeat test with a hold shunt - but it really shouldn't matter
# trigger a private and check for shunt and shunt expiry
ping -n -q -c 1 -I 192.1.3.209 192.1.3.46
# wait on OE retransmits and rekeying
sleep 3
# should show nothing in shuntstatus (shunt is not bare, but with conn),
# should show nothing in xfrm policy because SPI_HOLD (drop) is a no-op for XFRM as the larval state causes it already
# and should show show partial STATE
ipsec whack --shuntstatus
ip -o xfrm pol | grep 192.1.3.46
ipsec status | grep STATE_
sleep 10
# should show pass in shuntstatus and xfrm policy and without partial STATE
ipsec whack --shuntstatus
ip -o xfrm pol | grep 192.1.3.46
ipsec status | grep STATE_
sleep 35
# should show no more shunts for 192.1.3.46, no xfrm policy and no STATE's
ipsec whack --shuntstatus
ip -o xfrm pol | grep 192.1.3.46
ipsec status | grep STATE_

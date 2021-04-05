# confirm received delete was processed - should show no tunnel
ipsec whack --trafficstatus
# try triggering again, ondemand policy should re-trigger OE
ip xfrm state
ip xfrm pol
# we use a different trigger so we do not hit original left over larval state
hping -c 1 --udp  192.1.2.23
# wait on OE to re-establish IPsec SA
sleep 5
ip xfrm state
ip xfrm pol
# should show established tunnel and no bare shunts
ipsec whack --trafficstatus
ipsec whack --shuntstatus
# ping should succeed through tunnel
../../guestbin/ping-once.sh --up -I 192.1.3.209 192.1.2.23
ipsec whack --trafficstatus

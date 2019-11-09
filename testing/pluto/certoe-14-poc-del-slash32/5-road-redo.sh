# confirm received delete was processed - should show no tunnel
ipsec whack --trafficstatus
# let the old acquire expire so it won't interfere with our new trigger
sleep 5
# try triggering again, ondemand policy should re-trigger OE
ip xfrm state
ip xfrm pol
ping -n -c 1 -I 192.1.3.209 192.1.2.23
# wait on OE to re-establish IPsec SA
sleep 5
ip xfrm state
ip xfrm pol
# should show established tunnel and no bare shunts
ipsec whack --trafficstatus
ipsec whack --shuntstatus
# ping should succeed through tunnel
ping -n -c 2 -I 192.1.3.209 192.1.2.23
ipsec whack --trafficstatus

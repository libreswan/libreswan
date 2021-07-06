# matched by peer
ipsec auto --up road/0x1
# not matched by peer, should fail
ipsec auto --up road/0x2
# matched by peer
ipsec auto --up road/0x3
# not matched by peer, should fail
ipsec auto --up road/0x4
# There should be 2 tunnels up, and 2 broken tunnels
ipsec trafficstatus
ipsec showstates
echo done

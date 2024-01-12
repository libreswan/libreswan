# matched by peer
ipsec whack --impair revival
ipsec whack --impair suppress_retransmits
ipsec auto --up road/0x1
ipsec whack --impair none

# not matched by peer, should fail
ipsec whack --impair revival
ipsec auto --up road/0x2
ipsec whack --impair none

# matched by peer
ipsec whack --impair revival
ipsec whack --impair suppress_retransmits
ipsec auto --up road/0x3
ipsec whack --impair none

# not matched by peer, should fail
ipsec whack --impair revival
ipsec auto --up road/0x4
ipsec whack --impair none

# There should be 2 tunnels up, and 2 broken tunnels
ipsec trafficstatus
ipsec showstates

echo done

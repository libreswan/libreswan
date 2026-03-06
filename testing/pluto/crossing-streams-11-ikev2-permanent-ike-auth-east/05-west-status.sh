../../guestbin/wait-for.sh --match 'east-west' -- ipsec trafficstatus
ipsec showstates
ipsec status | grep "east-west"

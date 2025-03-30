# east will have stablished a connection
ipsec trafficstatus
ipsec showstates

# now check policy/state
ipsec _kernel policy

# wait for #1 to die
../../guestbin/wait-for.sh --no-match '#1:' -- ipsec showstates
ipsec _kernel policy


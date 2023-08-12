# east will have stablished a connection
ipsec trafficstatus
ipsec showstates

# now check policy/state
../../guestbin/ipsec-kernel-policy.sh

# wait for #1 to die
../../guestbin/wait-for.sh --no-match '#1:' -- ipsec showstates
../../guestbin/ipsec-kernel-policy.sh


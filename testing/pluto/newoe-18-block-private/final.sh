ipsec _kernel state
ipsec _kernel policy
# should not show any hits because block prevents trigger
grep "initiate on-demand" /tmp/pluto.log

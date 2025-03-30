ipsec _kernel state
ipsec _kernel policy
# should not show any hits because block prevents poc from seeing traffic
grep "initiate on-demand" /tmp/pluto.log

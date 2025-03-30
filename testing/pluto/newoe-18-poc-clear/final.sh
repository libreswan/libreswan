ipsec _kernel state
ipsec _kernel policy
# should not show any hits
grep -v '^|' /tmp/pluto.log | grep "^[^|].* established Child SA"

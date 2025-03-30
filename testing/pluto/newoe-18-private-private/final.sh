ipsec _kernel state
ipsec _kernel policy
# tunnel should have been established
grep "^[^|].* established Child SA" /tmp/pluto.log

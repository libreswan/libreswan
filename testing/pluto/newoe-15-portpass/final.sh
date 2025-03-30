ipsec _kernel state
ipsec _kernel policy
# A tunnel should have established
grep "^[^|].* established Child SA" /tmp/pluto.log

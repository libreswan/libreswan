ipsec _kernel state
ipsec _kernel policy
# should show tunnel
grep "^[^|].* established Child SA" /tmp/pluto.log

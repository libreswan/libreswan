ipsec _kernel state
ipsec _kernel policy
# a tunnel should show up here
grep "^[^|].* established Child SA" /tmp/pluto.log

ipsec whack --shuntstatus
ipsec _kernel state
ipsec _kernel policy
# should not show any hits
grep "^[^|].* established Child SA" /tmp/pluto.log

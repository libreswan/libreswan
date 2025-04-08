# should not match
grep 'Result using RFC 3947' /tmp/pluto.log || echo "OK - did not find a match"
# should not show udp encap
ipsec _kernel policy
ipsec _kernel state


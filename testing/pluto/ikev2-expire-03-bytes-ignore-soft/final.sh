ipsec _kernel state
ipsec _kernel policy
# should be absent
grep "initiating rekey to replace Child SA" OUTPUT/$(hostname).pluto.log
# should match on west twice
grep "initiating Child SA using IKE SA" OUTPUT/$(hostname).pluto.log || echo "success"
